/**
 * placeholder.ts — the redaction marker format.
 *
 * Read/log form (default everywhere): `[REDACTED:<ruleId>]`, no character of
 * the secret. Legacy form (0.1.1, opt-in with `last4: true`):
 * `[REDACTED:<ruleId>:<last4>]` when the match is at least 16 characters.
 * The bare `[REDACTED]` that triggers-api wrote is recognised too.
 *
 * `PLACEHOLDER_RE` is the idempotence guard: it recognizes ANY string this
 * module could have produced (regardless of ruleId/last4 content), so the
 * keyword rules can deny-list "the value IS already a placeholder" without the
 * placeholder's own bracket/colon punctuation re-triggering them on re-scan.
 */

const LAST4_THRESHOLD = 16;

/** Strip the `@secretlint/secretlint-rule-` / `mobilerun-redaction/` noise so
 *  the marker stays compact — e.g. `@secretlint/secretlint-rule-aws` -> `aws`. */
export function shortenRuleId(ruleId: string): string {
    return ruleId.replace(/^@secretlint\/secretlint-rule-/, '').replace(/^mobilerun-redaction\//, '');
}

export function buildPlaceholder(ruleId: string, matched: string): string {
    const shortId = shortenRuleId(ruleId);
    if (matched.length >= LAST4_THRESHOLD) {
        const last4 = matched.slice(-4);
        return `[REDACTED:${shortId}:${last4}]`;
    }
    return `[REDACTED:${shortId}]`;
}

/** The read/log form: `[REDACTED:<ruleId>]`, never a `:last4` suffix, so no
 *  character of a stored secret is exposed. This is what the sync path, the
 *  default async path and every read route emit. */
export function buildReadPlaceholder(ruleId: string): string {
    return `[REDACTED:${shortenRuleId(ruleId)}]`;
}

/** Matches any marker this module produces (with or without the `:last4`
 *  suffix) and the legacy bare `[REDACTED]`. Anchored (`^...$`) — only matches a
 *  value that IS entirely a placeholder, not one that merely contains one. */
export const PLACEHOLDER_RE = /^\[REDACTED(?::[^[\]:]+(?::[^[\]]*)?)?\]$/;

/** The same markers anywhere inside a string (global; use `.test` on a fresh
 *  copy or `matchAll`). Used by `restoreRedacted` and the sync rules. */
export const PLACEHOLDER_ANYWHERE_RE = /\[REDACTED(?::[^[\]:\s]+(?::[^[\]\s]*)?)?\]/;
