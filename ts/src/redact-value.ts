/**
 * Generic recursive JSON-value redaction (async: scanners + sync rules).
 *
 * Two rules, applied at every depth:
 *
 *   1. Structural skip keys (default `type`, `id`; `opts.skipKeys` replaces the
 *      set) keep their PRIMITIVE values byte for byte; containers under them
 *      are still walked.
 *   2. A string under a secret-named key (`isSecretKeyName`: `password`,
 *      `secret`, `token`, `apiKey`, `x-auth-token`, `Set-Cookie`, ...) is
 *      replaced even if it would not trip a scanner (for example a short,
 *      low-entropy password); so is a number under a singular secret key
 *      (`pin`), but not counts (`max_tokens`). Containers under such a key are
 *      walked and their strings replaced. The key is never touched.
 *
 * Other string values go through the normal `redactText` detector pass.
 *
 * KNOWN TRADE-OFFS:
 *   - Each STRING leaf is scanned independently. Secrets split across
 *     sibling leaves are not reassembled and therefore may not be detected.
 *   - Skipped primitive values are never scanned, even if they contain
 *     secret-shaped content.
 */
import { appendHits } from './hits.js';
import { redactText, type Hit, type RedactTextOpts } from './redact-text.js';
import { buildPlaceholder, buildReadPlaceholder } from './placeholder.js';
import { ALGORITHMS_SPEC } from './spec.js';
import { runStrictAsync, strictLimits, strictWalk } from './strict.js';
import {
    CREDENTIAL_KEY_RE,
    KEY_CONTEXT_RULE_ID,
    keyVerdict,
    leafPlaceholder,
    STRUCTURAL_SKIP_KEYS,
    strongerVerdict,
    type KeyVerdict,
} from './key-names.js';
import { setOwnKey } from './own-key.js';
import { isPrimitive } from './primitive.js';
import { redactKey } from './redact-key.js';

export { CREDENTIAL_KEY_RE, STRUCTURAL_SKIP_KEYS };

export type RedactValueStats = { hits: Hit[] };

export type RedactValueOpts = RedactTextOpts & {
    skipKeys?: ReadonlySet<string>;
    /** Limits of `mode: 'strict'` (ignored in `compat`): container depth and values. */
    maxDepth?: number;
    maxNodes?: number;
};

/** Recursively redact a JSON value. `opts.skipKeys` replaces the default
 *  structural skip set at every depth. */
export async function redactJsonValue(
    value: unknown,
    stats: RedactValueStats,
    opts: RedactValueOpts = {},
): Promise<unknown> {
    if (opts.mode === 'strict') return redactJsonValueStrict(value, stats, opts);
    return visit(value, stats, opts, 'none');
}

async function redactJsonValueStrict(
    value: unknown,
    stats: RedactValueStats,
    opts: RedactValueOpts,
): Promise<unknown> {
    const hits: Hit[] = [];
    try {
        const walk = strictWalk(value, strictLimits(opts), opts.skipKeys ?? STRUCTURAL_SKIP_KEYS, hits);
        const out = await runStrictAsync(walk, (text) => redactText(text, opts));
        appendHits(stats.hits, hits);
        return out;
    } catch {
        return buildReadPlaceholder(ALGORITHMS_SPEC.ruleIds.failed);
    }
}

async function visitString(
    value: string,
    stats: RedactValueStats,
    opts: RedactValueOpts,
    verdict: KeyVerdict,
): Promise<string> {
    if (value.length === 0) return value;
    const keyed = leafPlaceholder(verdict, value);
    if (keyed !== undefined) {
        stats.hits.push({ ruleId: KEY_CONTEXT_RULE_ID, range: [0, value.length] });
        if (opts.last4 === true) return buildPlaceholder(KEY_CONTEXT_RULE_ID, value);
        return keyed;
    }
    const { text, hits } = await redactText(value, opts);
    appendHits(stats.hits, hits);
    return text;
}

async function visit(
    value: unknown,
    stats: RedactValueStats,
    opts: RedactValueOpts,
    verdict: KeyVerdict,
): Promise<unknown> {
    if (typeof value === 'string') return visitString(value, stats, opts, verdict);
    if (Array.isArray(value)) {
        const out: unknown[] = [];
        for (const item of value) {
            out.push(await visit(item, stats, opts, verdict));
        }
        return out;
    }
    if (value !== null && typeof value === 'object') {
        return visitEntries(value as Record<string, unknown>, stats, opts, verdict);
    }
    const keyed = leafPlaceholder(verdict, value);
    if (keyed === undefined) return value;
    stats.hits.push({ ruleId: KEY_CONTEXT_RULE_ID, range: [0, 0] });
    return keyed;
}

async function visitEntries(
    value: Record<string, unknown>,
    stats: RedactValueStats,
    opts: RedactValueOpts,
    verdict: KeyVerdict,
): Promise<Record<string, unknown>> {
    const out: Record<string, unknown> = {};
    const skipKeys = opts.skipKeys ?? STRUCTURAL_SKIP_KEYS;
    for (const [key, child] of Object.entries(value)) {
        const outKey = redactKey(key, stats.hits);
        if (skipKeys.has(key) && isPrimitive(child)) {
            setOwnKey(out, outKey, child);
            continue;
        }
        const childVerdict = strongerVerdict(verdict, keyVerdict(key));
        setOwnKey(out, outKey, await visit(child, stats, opts, childVerdict));
    }
    return out;
}
