/**
 * Generic recursive JSON-value redaction.
 *
 * Two rules, applied at every depth:
 *
 *   1. Structural skip keys are never scanned or force-redacted, preserving
 *      identifiers byte-for-byte. The minimal default is `type` and `id`;
 *      consumers replace it with their own set through `opts.skipKeys`.
 *   2. A nonempty STRING value reached through a credential-suspicious key
 *      (`password`, `secret`, `token`, `apiKey`, `AWS_SECRET_ACCESS_KEY`, ...)
 *      is force-redacted even if the value alone would not trip a scanner
 *      (for example, a short, low-entropy password). The key is never touched.
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
import { buildPlaceholder } from './placeholder.js';

/** minimal default; consumers pass their own structural keys via `opts.skipKeys` */
export const STRUCTURAL_SKIP_KEYS: ReadonlySet<string> = new Set(['type', 'id']);

export const CREDENTIAL_KEY_RE = new RegExp(
    'password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|' +
    'private[_-]?key|client[_-]?secret|credential',
    'i',
);

export type RedactValueStats = { hits: Hit[] };

export type RedactValueOpts = RedactTextOpts & { skipKeys?: ReadonlySet<string> };

/** Recursively redact a JSON value. `opts.skipKeys` replaces the default
 *  structural skip set at every depth. */
export async function redactJsonValue(
    value: unknown,
    stats: RedactValueStats,
    opts: RedactValueOpts = {},
): Promise<unknown> {
    return visit(value, stats, undefined, opts);
}

/** `parentKey` is the object key this value was reached through. Array
 *  elements have no parent key; key-context applies only inside their objects. */
async function visit(
    value: unknown,
    stats: RedactValueStats,
    parentKey: string | undefined,
    opts: RedactValueOpts,
): Promise<unknown> {
    if (typeof value === 'string') {
        if (value.length === 0) return value;
        const hasCredentialKey = parentKey !== undefined && CREDENTIAL_KEY_RE.test(parentKey);
        if (hasCredentialKey) {
            const placeholder = buildPlaceholder('key-context', value);
            stats.hits.push({ ruleId: 'key-context', range: [0, value.length] });
            return placeholder;
        }
        const { text, hits } = await redactText(value, opts);
        stats.hits.push(...hits);
        return text;
    }
    if (Array.isArray(value)) {
        const out: unknown[] = [];
        for (const v of value) {
            out.push(await visit(v, stats, undefined, opts));
        }
        return out;
    }
    const isObject = value !== null && typeof value === 'object';
    if (isObject) {
        const out: Record<string, unknown> = {};
        const skipKeys = opts.skipKeys ?? STRUCTURAL_SKIP_KEYS;
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
            out[k] = skipKeys.has(k) ? v : await visit(v, stats, k, opts);
        }
        return out;
    }
    // number / boolean / null / undefined — nothing to redact.
    return value;
}
