/**
 * Generic recursive JSON-value redaction.
 *
 * Two rules, applied at every depth:
 *
 *   1. Structural skip keys are never scanned or force-redacted, preserving
 *      identifiers byte-for-byte. The minimal default is `type` and `id`;
 *      consumers replace it with their own set through `opts.skipKeys`.
 *   2. A nonempty string, a number, or a whole object/array reached through a
 *      secret-named key (`isSecretKeyName` in `key-names.ts`: `password`, `secret`,
 *      `token`, `apiKey`, `x-auth-token`, `Set-Cookie`, ...) is replaced as a
 *      unit even if it would not trip a scanner (for example, a short,
 *      low-entropy password). The key is never touched.
 *
 * Other string values go through the normal `redactText` detector pass.
 *
 * KNOWN TRADE-OFFS:
 *   - Each STRING leaf is scanned independently. Secrets split across
 *     sibling leaves are not reassembled and therefore may not be detected.
 *   - Skip-key fields are never scanned or force-redacted, even if they
 *     contain secret-shaped content. Consumers choose which values must
 *     remain byte-stable by supplying their own skip set.
 */
import { redactText, type Hit, type RedactTextOpts } from './redact-text.js';
import { setOwnKey } from './own-key.js';
import { buildPlaceholder } from './placeholder.js';
import { CREDENTIAL_KEY_RE, KEY_CONTEXT_RULE_ID, keyContextPlaceholder } from './key-names.js';

/** minimal default; consumers pass their own structural keys via `opts.skipKeys` */
export const STRUCTURAL_SKIP_KEYS: ReadonlySet<string> = new Set(['type', 'id']);

export { CREDENTIAL_KEY_RE };

export type RedactValueStats = { hits: Hit[] };

export type RedactValueOpts = RedactTextOpts & { skipKeys?: ReadonlySet<string> };

/** Recursively redact a JSON value. `opts.skipKeys` replaces the default
 *  structural skip set at every depth. */
export async function redactJsonValue(
    value: unknown,
    stats: RedactValueStats,
    opts: RedactValueOpts = {},
): Promise<unknown> {
    return visit(value, stats, opts);
}

async function visit(value: unknown, stats: RedactValueStats, opts: RedactValueOpts): Promise<unknown> {
    if (typeof value === 'string') {
        if (value.length === 0) return value;
        const { text, hits } = await redactText(value, opts);
        stats.hits.push(...hits);
        return text;
    }
    if (Array.isArray(value)) {
        const out: unknown[] = [];
        for (const v of value) {
            out.push(await visit(v, stats, opts));
        }
        return out;
    }
    const isObject = value !== null && typeof value === 'object';
    if (isObject) return visitEntries(value as Record<string, unknown>, stats, opts);
    // number / boolean / null / undefined — nothing to redact.
    return value;
}

async function visitEntries(
    value: Record<string, unknown>,
    stats: RedactValueStats,
    opts: RedactValueOpts,
): Promise<Record<string, unknown>> {
    const out: Record<string, unknown> = {};
    const skipKeys = opts.skipKeys ?? STRUCTURAL_SKIP_KEYS;
    for (const [key, child] of Object.entries(value)) {
        setOwnKey(out, key, skipKeys.has(key) ? child : await visitKeyed(key, child, stats, opts));
    }
    return out;
}

/** A value reached through an object key: replaced as a unit when the key is
 *  secret-named, otherwise visited. Array elements have no key context. */
async function visitKeyed(
    key: string,
    child: unknown,
    stats: RedactValueStats,
    opts: RedactValueOpts,
): Promise<unknown> {
    const placeholder = keyContextPlaceholder(key, child);
    if (placeholder === undefined) return visit(child, stats, opts);
    const length = typeof child === 'string' ? child.length : 0;
    stats.hits.push({ ruleId: KEY_CONTEXT_RULE_ID, range: [0, length] });
    if (opts.last4 === true && typeof child === 'string') return buildPlaceholder(KEY_CONTEXT_RULE_ID, child);
    return placeholder;
}
