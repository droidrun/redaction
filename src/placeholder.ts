/**
 * placeholder.ts — the redaction marker format.
 *
 * `[REDACTED:<ruleId>:<last4>]` when the match is long enough that the last 4
 * characters aren't a meaningful fraction of the secret (>=16 chars — below
 * that, last4 of e.g. an 8-char password would be 50% of the material);
 * otherwise the shorter `[REDACTED:<ruleId>]`.
 *
 * `PLACEHOLDER_RE` is the idempotence guard: it recognizes ANY string this
 * module could have produced (regardless of ruleId/last4 content), so
 * `generic-keyword-rule.ts` can deny-list "the value IS already a
 * placeholder" without the placeholder's own bracket/colon punctuation
 * re-triggering the keyword rule's value-evidence check on re-scan.
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

/** Matches any marker this module produces, with or without the `:last4`
 *  suffix. Anchored (`^...$`) — only rejects a value that IS entirely a
 *  placeholder, not one that merely contains one as a substring. */
export const PLACEHOLDER_RE = /^\[REDACTED:[^[\]:]+(?::[^[\]]*)?\]$/;
