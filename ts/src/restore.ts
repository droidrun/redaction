/**
 * restore.ts — `restoreRedacted(incoming, stored, opts?)`: the write-side
 * partner of redaction. A client that read redacted values and writes the
 * document back sends placeholders; this puts the stored values back, so a
 * read-modify-write never loses a secret by accident.
 *
 * Threat model: editors are secret owners. Whoever may edit and run a
 * resource holds its secrets anyway; redaction protects against read-only
 * roles, logs, spans and responses, not against editors. So restore does NOT
 * bind a secret to the fields around it: a changed `url` next to a placeholder
 * still restores. It only guarantees that a secret is never moved to another
 * item or path and never invented.
 *
 * Returns `{ value, conflicts }`. `conflicts` lists the JSON path of every
 * placeholder that could NOT be restored; its placeholder stays in `value`.
 * Nothing is dropped silently: a caller rejects the write or tells the client.
 *
 * A placeholder at a path keeps the stored value at the SAME path when that is
 * a non-placeholder string, number, object or array, and:
 *   - Matching. Objects match by key. Array items match by identity (`id` by
 *     default, or `opts.identify(item)`); an identity that occurs more than
 *     once on either side is ambiguous and matches nothing. Items with no
 *     identity on either side match by index only when both arrays have the
 *     same length. Otherwise the placeholder stays (conflict).
 *   - Strings. An incoming string that contains placeholders keeps the stored
 *     string only if its literal segments appear in the stored string in
 *     order, the first at the start and the last at the end; edited text
 *     around a placeholder is a conflict. A whole placeholder also restores a
 *     stored number, object or array (the legacy `[REDACTED]` replaced those).
 * Everything else takes `incoming` as sent: new keys and values win, removed
 * keys are gone, a placeholder with nothing restorable behind it (missing,
 * null, boolean, or itself a different placeholder) stays a placeholder and is a
 * conflict (a value is never invented). Pure; neither argument is mutated; a
 * key named `__proto__` is an ordinary key.
 */
import { setOwnKey } from './own-key.js';
import { literalSegments, PLACEHOLDER_ANYWHERE_RE, PLACEHOLDER_RE } from './placeholder.js';

export type RestoreOpts = {
    /** Identity of an array item, or `undefined` when it has none. Default: its `id`. */
    identify?: (item: unknown) => string | number | undefined;
};

export type RestoreResult = { value: unknown; conflicts: string[] };

type Ctx = { identify: (item: unknown) => string | undefined; conflicts: string[] };

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
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

function pathKey(path: string, key: string): string {
    return /^[A-Za-z_$][\w$]*$/.test(key) ? `${path}.${key}` : `${path}[${JSON.stringify(key)}]`;
}

function conflict(path: string, ctx: Ctx): void {
    ctx.conflicts.push(path);
}

function restoreString(incoming: string, stored: unknown, path: string, ctx: Ctx): unknown {
    if (!hasPlaceholder(incoming) || incoming === stored) return incoming;
    if (typeof stored === 'string' && !PLACEHOLDER_RE.test(stored) && segmentsMatch(incoming, stored)) {
        return stored;
    }
    if (PLACEHOLDER_RE.test(incoming) && isStructureOrNumber(stored)) return stored;
    conflict(path, ctx);
    return incoming;
}

function restoreRecord(
    incoming: Record<string, unknown>,
    stored: unknown,
    path: string,
    ctx: Ctx,
): unknown {
    const storedRecord = isRecord(stored) ? stored : undefined;
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(incoming)) {
        const counterpart = storedRecord && Object.hasOwn(storedRecord, key) ? storedRecord[key] : undefined;
        setOwnKey(out, key, restore(value, counterpart, pathKey(path, key), ctx));
    }
    return out;
}

/** How often each identity occurs in `items` (items without one are skipped). */
function identityCounts(items: unknown[], ctx: Ctx): Map<string, number> {
    const counts = new Map<string, number>();
    for (const item of items) {
        const identity = ctx.identify(item);
        if (identity !== undefined) counts.set(identity, (counts.get(identity) ?? 0) + 1);
    }
    return counts;
}

/** For each incoming item, the stored item it matches (or `undefined`). */
function matchItems(incoming: unknown[], stored: unknown[] | undefined, ctx: Ctx): unknown[] {
    if (stored === undefined) return incoming.map(() => undefined);
    const incomingCounts = identityCounts(incoming, ctx);
    const storedCounts = identityCounts(stored, ctx);
    const storedByIdentity = new Map<string, unknown>();
    for (const item of stored) {
        const identity = ctx.identify(item);
        if (identity !== undefined) storedByIdentity.set(identity, item);
    }
    const sameLength = incoming.length === stored.length;
    return incoming.map((item, index) => {
        const identity = ctx.identify(item);
        if (identity !== undefined) {
            const unique = incomingCounts.get(identity) === 1 && storedCounts.get(identity) === 1;
            return unique ? storedByIdentity.get(identity) : undefined;
        }
        const candidate = stored[index];
        return sameLength && ctx.identify(candidate) === undefined ? candidate : undefined;
    });
}

function restoreArray(incoming: unknown[], stored: unknown, path: string, ctx: Ctx): unknown {
    const storedArray = Array.isArray(stored) ? stored : undefined;
    const matches = matchItems(incoming, storedArray, ctx);
    return incoming.map((item, index) => restore(item, matches[index], `${path}[${index}]`, ctx));
}

function restore(incoming: unknown, stored: unknown, path: string, ctx: Ctx): unknown {
    if (typeof incoming === 'string') return restoreString(incoming, stored, path, ctx);
    if (Array.isArray(incoming)) return restoreArray(incoming, stored, path, ctx);
    if (isRecord(incoming)) return restoreRecord(incoming, stored, path, ctx);
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
    const value = restore(incoming, stored, '$', ctx);
    return { value, conflicts: ctx.conflicts };
}
