/**
 * redact-value.ts — generic recursive JSON-value redaction, shared by the
 * contract-aware parts visitor (`parts.ts`) and any plain-JSON callers (bug
 * report `context`).
 *
 * Two rules, applied at every depth:
 *
 *   1. Structural skip-list: keys that are identifiers/enums per the
 *      `@droidrun/agent-stream-contract` part schemas (`type`, `id`,
 *      `toolCallId`, `state`, `toolName`, `questionId`, attachment
 *      `fileId`/`mimeType`/`filename`/`url`, ...) are never scanned OR
 *      force-redacted — a UUID or enum value coincidentally tripping the
 *      generic-keyword entropy check must never corrupt an id the FE/DB
 *      joins on.
 *   2. Key-context rule: a STRING value reached through a credential-
 *      suspicious key (`password`, `secret`, `token`, `apiKey`,
 *      `AWS_SECRET_ACCESS_KEY`, ...) is force-redacted even if the value
 *      alone wouldn't trip any secretlint rule (e.g. a short, low-entropy
 *      password) — the key name itself is the evidence. The key is never
 *      touched, only the value.
 *
 * Neither rule is a shortcut around the other: a key can be BOTH
 * non-structural and non-suspicious, in which case the value still goes
 * through the normal `redactText` detector pass.
 *
 * KNOWN TRADE-OFFS (disclosed, not fixed by this wave):
 *   - Each STRING leaf is scanned independently. A secret that happens to be
 *     SPLIT across two sibling leaves (e.g. one JSON field holds the first
 *     half of a key, another holds the second half) is not reassembled and
 *     therefore not detected — this walk has no cross-leaf lookback/lookahead.
 *   - `STRUCTURAL_SKIP_KEYS` fields (url, filename, etc.) are never scanned
 *     OR force-redacted, even if their string value happens to embed
 *     something secret-shaped (e.g. a token baked into a query string) —
 *     intentional, to keep FE/DB join keys byte-stable.
 */
import { redactText, type Hit, type RedactTextOpts } from './redact-text.js';
import { buildPlaceholder } from './placeholder.js';

// Derived from @droidrun/agent-stream-contract/src/parts.ts: identifiers,
// enums, and attachment display fields that must survive byte-for-byte for
// the FE/DB to keep working (reconciliation keys, joins, enum unions).
export const STRUCTURAL_SKIP_KEYS = new Set([
    'type',
    'id',
    'toolCallId',
    'state',
    'toolName',
    'questionId',
    'questionID',
    'fileId',
    'mimeType',
    'filename',
    'url',
    'status',
    'errorClass',
    'deviceId',
    'verb',
    'buildId',
    'phase',
    'slug',
    'agentName',
    'messageId',
    'eventType',
    // Charset-validated avatar identifier, never credential content.
    'avatarSeed',
    'code',
]);

export const CREDENTIAL_KEY_RE = new RegExp(
    'password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|' +
    'private[_-]?key|client[_-]?secret|credential',
    'i',
);

export type RedactValueStats = { hits: Hit[] };

/**
 * Recursively redact a JSON value. `parentKey` is the object key this value
 * was reached through (undefined for the root call and for array elements —
 * arrays have no keys, so the key-context rule never applies to their
 * elements directly, only to nested objects inside them). `opts.skipKeys`
 * replaces the default structural skip set at every depth.
 */
export async function redactJsonValue(
    value: unknown,
    stats: RedactValueStats,
    parentKey?: string,
    opts: RedactTextOpts & { skipKeys?: ReadonlySet<string> } = {},
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
        if (hits.length > 0) stats.hits.push(...hits);
        return text;
    }
    if (Array.isArray(value)) {
        const out: unknown[] = [];
        for (const v of value) {
            out.push(await redactJsonValue(v, stats, undefined, opts));
        }
        return out;
    }
    const isObject = value !== null && typeof value === 'object';
    if (isObject) {
        const out: Record<string, unknown> = {};
        const skipKeys = opts.skipKeys ?? STRUCTURAL_SKIP_KEYS;
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
            out[k] = skipKeys.has(k) ? v : await redactJsonValue(v, stats, k, opts);
        }
        return out;
    }
    // number / boolean / null / undefined — nothing to redact.
    return value;
}
