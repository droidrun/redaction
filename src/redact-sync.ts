/**
 * redact-sync.ts — the sync entry: deterministic regex rules only (see
 * `sync-rules.ts`) plus key-name redaction for JSON. For logs, spans, error
 * bodies and other hot paths. No secretlint scanners, no promises.
 *
 * Unlike the async path (which fails open), the sync path is bounded and
 * FAILS CLOSED: text or structure beyond a limit, and anything that throws,
 * is replaced by a placeholder rather than passed through. Limits:
 *   - `maxChars`: characters scanned per call (text) or in total (JSON);
 *     the rest becomes `[REDACTED:size-limit]`.
 *   - `maxDepth`: container nesting; deeper becomes `[REDACTED:depth-limit]`.
 *   - `maxNodes`: values visited; the rest becomes `[REDACTED:size-limit]`.
 * Circular references become `[REDACTED:circular]`.
 */
import { applyHits, type Hit } from './hits.js';
import { keyContextPlaceholder, KEY_CONTEXT_RULE_ID } from './key-names.js';
import { buildReadPlaceholder } from './placeholder.js';
import { detectSyncHits } from './sync-rules.js';
import { setOwnKey } from './own-key.js';

const SYNC_DEFAULT_MAX_CHARS = 4_000_000;
const SYNC_DEFAULT_MAX_DEPTH = 64;
const SYNC_DEFAULT_MAX_NODES = 100_000;

const SIZE_LIMIT = 'size-limit';
const DEPTH_LIMIT = 'depth-limit';
const CIRCULAR = 'circular';
const FAILED = 'redaction-failed';

/** Below this no rule can match (`Bearer x` is the shortest secret context). */
const MIN_SCAN_LEN = 8;

export type RedactTextSyncOpts = { maxChars?: number };

export type RedactJsonSyncOpts = {
    maxChars?: number;
    maxDepth?: number;
    maxNodes?: number;
    /** Replaces the default structural skip set (`type`, `id`) at every depth. */
    skipKeys?: ReadonlySet<string>;
    /** Receives the hits (rule id and range only, never the matched text). */
    stats?: { hits: Hit[] };
};

function isSkipDefault(key: string): boolean {
    return key === 'type' || key === 'id';
}

function scanText(text: string, maxChars: number): { text: string; hits: Hit[] } {
    if (text.length < MIN_SCAN_LEN) return { text, hits: [] };
    const capped = text.length > maxChars;
    const scanned = capped ? text.slice(0, maxChars) : text;
    const hits = detectSyncHits(scanned);
    const redacted = applyHits(scanned, hits);
    if (!capped) return { text: redacted, hits };
    const tail: Hit = { ruleId: SIZE_LIMIT, range: [maxChars, text.length] };
    return { text: redacted + buildReadPlaceholder(SIZE_LIMIT), hits: [...hits, tail] };
}

/** Redact a string with the sync rules. Never throws; on an internal failure
 *  the whole text is replaced. */
export function redactTextSync(
    text: string,
    opts: RedactTextSyncOpts = {},
): { text: string; hits: Hit[] } {
    try {
        return scanText(text, opts.maxChars ?? SYNC_DEFAULT_MAX_CHARS);
    } catch {
        return { text: buildReadPlaceholder(FAILED), hits: [{ ruleId: FAILED, range: [0, text.length] }] };
    }
}

type Walk = {
    nodes: number;
    chars: number;
    maxDepth: number;
    skip: (key: string) => boolean;
    hits: Hit[];
    ancestors: WeakSet<object>;
};

function limit(ruleId: string, state: Walk): string {
    state.hits.push({ ruleId, range: [0, 0] });
    return buildReadPlaceholder(ruleId);
}

function walkString(value: string, state: Walk): string {
    if (value.length === 0) return value;
    if (state.chars <= 0) return limit(SIZE_LIMIT, state);
    const { text, hits } = scanText(value, state.chars);
    state.chars -= Math.min(value.length, state.chars);
    state.hits.push(...hits);
    return text;
}

function walkEntries(value: object, depth: number, state: Walk): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
        if (state.skip(key)) {
            setOwnKey(out, key, child);
            continue;
        }
        const placeholder = keyContextPlaceholder(key, child);
        if (placeholder === undefined) {
            setOwnKey(out, key, walk(child, depth + 1, state));
            continue;
        }
        const length = typeof child === 'string' ? child.length : 0;
        state.hits.push({ ruleId: KEY_CONTEXT_RULE_ID, range: [0, length] });
        setOwnKey(out, key, placeholder);
    }
    return out;
}

function walk(value: unknown, depth: number, state: Walk): unknown {
    if (typeof value === 'string') return walkString(value, state);
    if (value === null || typeof value !== 'object' || value instanceof Date) return value;
    if (state.nodes <= 0) return limit(SIZE_LIMIT, state);
    state.nodes -= 1;
    if (depth >= state.maxDepth) return limit(DEPTH_LIMIT, state);
    if (state.ancestors.has(value)) return limit(CIRCULAR, state);
    state.ancestors.add(value);
    try {
        if (Array.isArray(value)) return value.map((item) => walk(item, depth + 1, state));
        return walkEntries(value, depth, state);
    } finally {
        state.ancestors.delete(value);
    }
}

/** Redact a JSON-shaped value with the sync rules and the key-name rule: any
 *  string leaf is scanned; a string, number or whole object/array under a
 *  secret-named key is replaced as a unit. Never throws; on an internal
 *  failure the whole value is replaced. */
export function redactJsonValueSync(value: unknown, opts: RedactJsonSyncOpts = {}): unknown {
    const skipKeys = opts.skipKeys;
    const state: Walk = {
        nodes: opts.maxNodes ?? SYNC_DEFAULT_MAX_NODES,
        chars: opts.maxChars ?? SYNC_DEFAULT_MAX_CHARS,
        maxDepth: opts.maxDepth ?? SYNC_DEFAULT_MAX_DEPTH,
        skip: skipKeys ? (key) => skipKeys.has(key) : isSkipDefault,
        hits: [],
        ancestors: new WeakSet(),
    };
    try {
        const out = walk(value, 0, state);
        opts.stats?.hits.push(...state.hits);
        return out;
    } catch {
        return buildReadPlaceholder(FAILED);
    }
}
