/**
 * restore.ts — `restoreRedacted(incoming, stored, opts?)`: the write-side
 * partner of redaction. A client that read redacted values and writes the
 * document back sends placeholders; this puts the stored values back where
 * that is SAFE, so a read-modify-write never destroys a secret, and never
 * attaches a stored secret to something the client changed around it.
 *
 * Returns `{ value, conflicts }`. `conflicts` lists the JSON path of every
 * placeholder that could NOT be restored; its placeholder stays in `value`.
 * Nothing is dropped silently: a caller rejects the write or tells the client.
 *
 * A placeholder keeps the stored value only when ALL hold:
 *   - Matching. Objects match by key. Array items match by identity (`id` by
 *     default, or `opts.identify(item)`); the n-th item with a given identity
 *     matches the n-th stored one. Items with no identity on either side match
 *     by index only when both arrays have the same length.
 *   - Ancestor chain unchanged (L1). Along the path from the placeholder's
 *     object up to and including the nearest array item (or the root when
 *     there is none), every non-secret-named primitive value (url, host,
 *     method, …) equals the stored one (a value that itself carries a
 *     placeholder must match its stored string, below). Otherwise a client
 *     could redirect a stored secret to a new destination by keeping its
 *     placeholder, also from a level above it (`{ url, headers: { Authorization } }`).
 *     Keys added or removed count as changes. Display-only keys (`name`,
 *     `title`, `label`, `description`, `comment`, `notes`, `position`, `order`,
 *     `index`, `updatedAt`, `createdAt`) are ignored, so renaming a step does not
 *     block it; a change in another array item, or above the array, does not either.
 *   - Strings. An incoming string that contains placeholders keeps the stored
 *     string only if its literal segments appear in the stored string in
 *     order, the first at the start and the last at the end; edited text
 *     around a placeholder is a conflict. A whole placeholder also restores a
 *     stored number, object or array (the legacy `[REDACTED]` replaced those).
 * Everything else takes `incoming` as sent: new keys and values win, removed
 * keys are gone, a placeholder with nothing stored behind it stays a
 * placeholder and is a conflict (a value is never invented). Pure; neither
 * argument is mutated; a key named `__proto__` is an ordinary key.
 */
import { isSecretKeyName } from './key-names.js';
import { setOwnKey } from './own-key.js';
import { literalSegments, PLACEHOLDER_ANYWHERE_RE, PLACEHOLDER_RE } from './placeholder.js';

export type RestoreOpts = {
    /** Identity of an array item, or `undefined` when it has none. Default: its `id`. */
    identify?: (item: unknown) => string | number | undefined;
};

export type RestoreResult = { value: unknown; conflicts: string[] };

/** Keys that only describe or order an item: changing them never moves a secret. */
const DISPLAY_KEYS = new Set([
    'name', 'title', 'label', 'description', 'comment', 'notes', 'position', 'order', 'index',
    'updatedat', 'createdat',
]);

type Ctx = { identify: (item: unknown) => string | undefined; conflicts: string[] };

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPrimitive(value: unknown): boolean {
    return value === null || (typeof value !== 'object' && typeof value !== 'function');
}

function hasPlaceholder(text: string): boolean {
    return PLACEHOLDER_ANYWHERE_RE.test(text);
}

/** Whether `stored` can be what `incoming` (holding placeholders) was redacted from. */
function segmentsMatch(incoming: string, stored: string): boolean {
    const segments = literalSegments(incoming);
    const first = segments[0] ?? '';
    const last = segments[segments.length - 1] ?? '';
    const fits = stored.length >= first.length + last.length;
    if (!fits || !stored.startsWith(first) || !stored.endsWith(last)) return false;
    const end = stored.length - last.length;
    let position = first.length;
    for (const segment of segments.slice(1, -1)) {
        const at = stored.indexOf(segment, position);
        if (at === -1 || at + segment.length > end) return false;
        position = at + segment.length;
    }
    return true;
}

/** A whole placeholder can stand for a stored number or container (a numeric secret, a limit marker). */
function isStructureOrNumber(value: unknown): boolean {
    const isNumber = typeof value === 'number' || typeof value === 'bigint';
    return isNumber || (typeof value === 'object' && value !== null);
}

function sameOrRedactedFrom(incoming: unknown, stored: unknown): boolean {
    if (incoming === stored) return true;
    const whole = typeof incoming === 'string' && PLACEHOLDER_RE.test(incoming);
    if (whole && isStructureOrNumber(stored)) return true;
    return typeof incoming === 'string' && typeof stored === 'string' && hasPlaceholder(incoming) &&
        segmentsMatch(incoming, stored);
}

function pathKey(path: string, key: string): string {
    return /^[A-Za-z_$][\w$]*$/.test(key) ? `${path}.${key}` : `${path}[${JSON.stringify(key)}]`;
}

function conflict(path: string, ctx: Ctx): void {
    ctx.conflicts.push(path);
}

/** Primitive, non-secret-named, non-display values: the destination-like fields. */
function siblingsUnchanged(incoming: Record<string, unknown>, stored: Record<string, unknown>): boolean {
    const keys = new Set([...Object.keys(incoming), ...Object.keys(stored)]);
    for (const key of keys) {
        if (isSecretKeyName(key) || DISPLAY_KEYS.has(key.toLowerCase())) continue;
        const inc = Object.hasOwn(incoming, key) ? incoming[key] : undefined;
        const sto = Object.hasOwn(stored, key) ? stored[key] : undefined;
        if (!isPrimitive(inc) && !isPrimitive(sto)) continue;
        if (inc === undefined || sto === undefined) return false;
        if (!sameOrRedactedFrom(inc, sto)) return false;
    }
    return true;
}

function restoreString(incoming: string, stored: unknown, path: string, ctx: Ctx, allowed: boolean): unknown {
    if (!hasPlaceholder(incoming)) return incoming;
    if (allowed && typeof stored === 'string' && segmentsMatch(incoming, stored)) return stored;
    if (allowed && PLACEHOLDER_RE.test(incoming) && isStructureOrNumber(stored)) return stored;
    conflict(path, ctx);
    return incoming;
}

function restoreRecord(
    incoming: Record<string, unknown>,
    stored: unknown,
    path: string,
    ctx: Ctx,
    chainOk: boolean,
): unknown {
    const storedRecord = isRecord(stored) ? stored : undefined;
    const allowed = chainOk && storedRecord !== undefined && siblingsUnchanged(incoming, storedRecord);
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(incoming)) {
        const counterpart = storedRecord && Object.hasOwn(storedRecord, key) ? storedRecord[key] : undefined;
        setOwnKey(out, key, restore(value, counterpart, pathKey(path, key), ctx, allowed));
    }
    return out;
}

/** For each incoming item, the stored item it matches (or `undefined`). */
function matchItems(incoming: unknown[], stored: unknown[] | undefined, ctx: Ctx): unknown[] {
    if (stored === undefined) return incoming.map(() => undefined);
    const byIdentity = new Map<string, number[]>();
    stored.forEach((item, index) => {
        const identity = ctx.identify(item);
        if (identity !== undefined) byIdentity.set(identity, [...(byIdentity.get(identity) ?? []), index]);
    });
    const sameLength = incoming.length === stored.length;
    return incoming.map((item, index) => {
        const identity = ctx.identify(item);
        if (identity !== undefined) {
            const index0 = byIdentity.get(identity)?.shift();
            return index0 === undefined ? undefined : stored[index0];
        }
        const candidate = stored[index];
        return sameLength && ctx.identify(candidate) === undefined ? candidate : undefined;
    });
}

function restoreArray(
    incoming: unknown[],
    stored: unknown,
    path: string,
    ctx: Ctx,
    chainOk: boolean,
): unknown {
    const storedArray = Array.isArray(stored) ? stored : undefined;
    const matches = matchItems(incoming, storedArray, ctx);
    // Primitive items (strings holding placeholders) are matched by index, so
    // every primitive item must be unchanged for them to count as restorable.
    const primitivesOk = chainOk && storedArray !== undefined && incoming.length === storedArray.length &&
        incoming.every((item, index) => !isPrimitive(item) || sameOrRedactedFrom(item, matches[index]));
    // An array item starts a new chain: what changed above it does not bind its secrets.
    return incoming.map((item, index) => {
        const itemChainOk = isPrimitive(item) ? primitivesOk : true;
        return restore(item, matches[index], `${path}[${index}]`, ctx, itemChainOk);
    });
}

function restore(incoming: unknown, stored: unknown, path: string, ctx: Ctx, chainOk: boolean): unknown {
    if (typeof incoming === 'string') return restoreString(incoming, stored, path, ctx, chainOk);
    if (Array.isArray(incoming)) return restoreArray(incoming, stored, path, ctx, chainOk);
    if (isRecord(incoming)) return restoreRecord(incoming, stored, path, ctx, chainOk);
    return incoming;
}

function defaultIdentify(item: unknown): string | undefined {
    if (!isRecord(item) || !Object.hasOwn(item, 'id')) return undefined;
    const id = item.id;
    return typeof id === 'string' || typeof id === 'number' ? String(id) : undefined;
}

export function restoreRedacted(incoming: unknown, stored: unknown, opts: RestoreOpts = {}): RestoreResult {
    const identify = opts.identify;
    const ctx: Ctx = {
        identify: identify
            ? (item) => {
                const identity = identify(item);
                return identity === undefined ? undefined : String(identity);
            }
            : defaultIdentify,
        conflicts: [],
    };
    const value = restore(incoming, stored, '$', ctx, true);
    return { value, conflicts: ctx.conflicts };
}
