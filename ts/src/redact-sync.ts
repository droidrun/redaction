/**
 * redact-sync.ts — the sync entry: deterministic regex rules only (see
 * `sync-rules.ts`) plus key-name redaction for JSON. For logs, spans, error
 * bodies and other hot paths. No secretlint scanners, no promises.
 *
 * Unlike the async path (which fails open), the sync path is bounded and
 * FAILS CLOSED: text or structure beyond a limit, and anything that throws,
 * is replaced by a placeholder rather than passed through. Limits:
 *   - `maxChars`: characters per text, or in total across a JSON value; a text
 *     or leaf over the limit is replaced whole (no prefix is exposed).
 *   - `maxNodes`: values visited (every leaf and container counts); on
 *     exhaustion traversal stops and the rest becomes `[REDACTED:size-limit]`.
 *   - `maxDepth`: container nesting; deeper becomes `[REDACTED:depth-limit]`.
 * Circular references become `[REDACTED:circular]`. Typed arrays and buffers
 * become `[REDACTED:size-limit]`; an `Error` is read as name/message/stack and
 * an object with `toJSON` as its `toJSON()` result, then scanned.
 */
import { appendHits, applyHits, type Hit } from './hits.js';
import type { RedactMode } from './mode.js';
import {
    KEY_CONTEXT_RULE_ID,
    keyVerdict,
    leafPlaceholder,
    STRUCTURAL_SKIP_KEYS,
    strongerVerdict,
    type KeyVerdict,
} from './key-names.js';
import { setOwnKey } from './own-key.js';
import { placeKey, type KeySlots } from './place-key.js';
import { isPrimitive } from './primitive.js';
import { redactKey } from './redact-key.js';
import { buildReadPlaceholder } from './placeholder.js';
import { ALGORITHMS_SPEC } from './spec.js';
import { runStrictSync, spliceHits, strictLimits, strictWalk, type LeafResult } from './strict.js';
import { detectSyncHits } from './sync-rules.js';

const { sync: SYNC_LIMITS, ruleIds: RULE_IDS, text: TEXT_SPEC } = ALGORITHMS_SPEC;
const SIZE_LIMIT = RULE_IDS.sizeLimit;
const DEPTH_LIMIT = RULE_IDS.depthLimit;
const CIRCULAR = RULE_IDS.circular;
const FAILED = RULE_IDS.failed;

/** Below this no rule can match (`Bearer x` is the shortest secret context). */
const MIN_SCAN_LEN = TEXT_SPEC.minScanLength;

export type RedactTextSyncOpts = {
    maxChars?: number;
    /** `strict` additionally never passes an unscanned value (see `mode.ts`); default `compat`. */
    mode?: RedactMode;
};

export type RedactJsonSyncOpts = {
    maxChars?: number;
    maxDepth?: number;
    maxNodes?: number;
    /** `strict` walks iteratively and keeps to the limits (see `strict.ts`); default `compat`. */
    mode?: RedactMode;
    /** Replaces the default structural skip set (`type`, `id`): primitive values under
     *  these keys are kept as they are; containers under them are still walked. */
    skipKeys?: ReadonlySet<string>;
    /** Receives the hits (rule id and range only, never the matched text). */
    stats?: { hits: Hit[] };
};

function scanText(text: string, maxChars: number): { text: string; hits: Hit[] } {
    if (text.length > maxChars) {
        const hit: Hit = { ruleId: SIZE_LIMIT, range: [0, text.length] };
        return { text: buildReadPlaceholder(SIZE_LIMIT), hits: [hit] };
    }
    if (text.length < MIN_SCAN_LEN) return { text, hits: [] };
    const hits = detectSyncHits(text);
    return { text: applyHits(text, hits), hits };
}

/** Redact a string with the sync rules. Never throws (a non-string is turned
 *  into one); on an internal failure the whole text is replaced. */
export function redactTextSync(
    text: string,
    opts: RedactTextSyncOpts = {},
): { text: string; hits: Hit[] } {
    try {
        const source = typeof text === 'string' ? text : String(text);
        return scanText(source, opts.maxChars ?? SYNC_LIMITS.maxChars);
    } catch {
        return { text: buildReadPlaceholder(FAILED), hits: [{ ruleId: FAILED, range: [0, 0] }] };
    }
}

type Walk = {
    nodes: number;
    chars: number;
    maxDepth: number;
    skip: ReadonlySet<string>;
    hits: Hit[];
    ancestors: WeakSet<object>;
};

function limit(ruleId: string, state: Walk): string {
    state.hits.push({ ruleId, range: [0, 0] });
    return buildReadPlaceholder(ruleId);
}

function walkString(value: string, verdict: KeyVerdict, state: Walk): string {
    if (value.length === 0) return value;
    const keyed = leafPlaceholder(verdict, value);
    if (keyed !== undefined) {
        state.hits.push({ ruleId: KEY_CONTEXT_RULE_ID, range: [0, value.length] });
        return keyed;
    }
    if (value.length > state.chars) {
        state.chars = 0;
        return limit(SIZE_LIMIT, state);
    }
    state.chars -= value.length;
    const { text, hits } = scanText(value, Number.MAX_SAFE_INTEGER);
    appendHits(state.hits, hits);
    return text;
}

function walkPrimitive(value: unknown, verdict: KeyVerdict, state: Walk): unknown {
    if (typeof value === 'string') return walkString(value, verdict, state);
    const keyed = leafPlaceholder(verdict, value);
    if (keyed === undefined) return value;
    state.hits.push({ ruleId: KEY_CONTEXT_RULE_ID, range: [0, 0] });
    return keyed;
}

function walkEntries(
    value: object,
    depth: number,
    verdict: KeyVerdict,
    state: Walk,
): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    const slots: KeySlots = new Map();
    for (const key in value) {
        if (!Object.hasOwn(value, key)) continue;
        if (state.nodes <= 0) {
            setOwnKey(out, key, limit(SIZE_LIMIT, state));
            break;
        }
        const child = (value as Record<string, unknown>)[key];
        const outKey = redactKey(key, state.hits);
        if (state.skip.has(key) && isPrimitive(child)) {
            state.nodes -= 1;
            placeKey(out, slots, outKey, child);
            continue;
        }
        const childVerdict = strongerVerdict(verdict, keyVerdict(key));
        placeKey(out, slots, outKey, walk(child, depth + 1, childVerdict, state));
    }
    return out;
}

function walkArray(value: unknown[], depth: number, verdict: KeyVerdict, state: Walk): unknown[] {
    const out: unknown[] = [];
    for (let index = 0; index < value.length; index++) {
        if (state.nodes <= 0) {
            out.push(limit(SIZE_LIMIT, state));
            break;
        }
        out.push(walk(value[index], depth + 1, verdict, state));
    }
    return out;
}

/** Error and `toJSON` objects are read the way JSON.stringify would, then scanned. */
function plainView(value: object): unknown {
    if (value instanceof Error) return { name: value.name, message: value.message, stack: value.stack };
    const toJson = (value as { toJSON?: unknown }).toJSON;
    return typeof toJson === 'function' ? toJson.call(value) : value;
}

function walkContainer(value: object, depth: number, verdict: KeyVerdict, state: Walk): unknown {
    if (state.ancestors.has(value)) return limit(CIRCULAR, state);
    state.ancestors.add(value);
    try {
        const view = plainView(value);
        if (view !== value) return walk(view, depth, verdict, state);
        if (Array.isArray(value)) return walkArray(value, depth, verdict, state);
        return walkEntries(value, depth, verdict, state);
    } finally {
        state.ancestors.delete(value);
    }
}

function walk(value: unknown, depth: number, verdict: KeyVerdict, state: Walk): unknown {
    if (state.nodes <= 0) return limit(SIZE_LIMIT, state);
    state.nodes -= 1;
    if (isPrimitive(value)) return walkPrimitive(value, verdict, state);
    if (typeof value !== 'object' || value === null) return value;
    if (value instanceof Date) return value;
    if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return limit(SIZE_LIMIT, state);
    if (depth >= state.maxDepth) return limit(DEPTH_LIMIT, state);
    return walkContainer(value, depth, verdict, state);
}

/** The strict leaf scan: the sync rules, and a placeholder for the whole leaf when they fail. */
function strictLeaf(text: string): LeafResult {
    try {
        return text.length < MIN_SCAN_LEN ? { text, hits: [] } : spliceHits(text, detectSyncHits(text));
    } catch {
        return { text: buildReadPlaceholder(FAILED), hits: [{ ruleId: FAILED, range: [0, 0] }] };
    }
}

function redactJsonValueStrictSync(value: unknown, opts: RedactJsonSyncOpts): unknown {
    const hits: Hit[] = [];
    try {
        const limits = strictLimits(opts);
        const skip = opts.skipKeys ?? STRUCTURAL_SKIP_KEYS;
        const out = runStrictSync(strictWalk(value, limits, skip, hits), strictLeaf);
        if (opts.stats) appendHits(opts.stats.hits, hits);
        return out;
    } catch {
        return buildReadPlaceholder(FAILED);
    }
}

/** Redact a JSON-shaped value with the sync rules and the key-name rule: any
 *  string leaf is scanned; a string under a secret-named key is replaced, and
 *  so is a number under a singular secret key (`pin`, `password`; not
 *  `max_tokens`). Containers under a secret key are walked. Never throws; on
 *  an internal failure the whole value is replaced. */
export function redactJsonValueSync(value: unknown, opts: RedactJsonSyncOpts = {}): unknown {
    if (opts.mode === 'strict') return redactJsonValueStrictSync(value, opts);
    const state: Walk = {
        nodes: opts.maxNodes ?? SYNC_LIMITS.maxNodes,
        chars: opts.maxChars ?? SYNC_LIMITS.maxChars,
        maxDepth: opts.maxDepth ?? SYNC_LIMITS.maxDepth,
        skip: opts.skipKeys ?? STRUCTURAL_SKIP_KEYS,
        hits: [],
        ancestors: new WeakSet(),
    };
    try {
        const out = walk(value, 0, 'none', state);
        if (opts.stats) appendHits(opts.stats.hits, state.hits);
        return out;
    } catch {
        return buildReadPlaceholder(FAILED);
    }
}
