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

/** Brackets would end a placeholder early, so they are masked in the last4. */
function safeLast4(matched: string): string {
    return matched.slice(-4).replace(/[[\]]/g, '*');
}

export function buildPlaceholder(ruleId: string, matched: string): string {
    const shortId = shortenRuleId(ruleId);
    if (matched.length >= LAST4_THRESHOLD) {
        return `[REDACTED:${shortId}:${safeLast4(matched)}]`;
    }
    return `[REDACTED:${shortId}]`;
}

/** The read/log form: `[REDACTED:<ruleId>]`, never a `:last4` suffix, so no
 *  character of a stored secret is exposed. This is what the sync path, the
 *  default async path and every read route emit. */
export function buildReadPlaceholder(ruleId: string): string {
    return `[REDACTED:${shortenRuleId(ruleId)}]`;
}

// One grammar for every check. Forms: the bare legacy `[REDACTED]`,
// `[REDACTED:<rule>]`, `[REDACTED:<rule>:<last4>]`. The rule has no brackets,
// colons or whitespace; the suffix is whatever `buildPlaceholder` can emit
// (any four characters except brackets, spaces included).
const PLACEHOLDER_SOURCE = String.raw`\[REDACTED(?::[^[\]:\s]+(?::[^[\]]*)?)?\]`;

/** Matches a string that IS one placeholder (anchored): any of the three forms. */
export const PLACEHOLDER_RE = new RegExp(`^${PLACEHOLDER_SOURCE}$`);

/** A placeholder anywhere in a string (not anchored, not global). Internal. */
export const PLACEHOLDER_ANYWHERE_RE = new RegExp(PLACEHOLDER_SOURCE);

const PLACEHOLDER_STICKY_RE = new RegExp(PLACEHOLDER_SOURCE, 'y');
const PLACEHOLDER_GLOBAL_RE = new RegExp(PLACEHOLDER_SOURCE, 'g');

/** End index of the placeholder starting exactly at `start`, or -1. */
export function placeholderEndAt(text: string, start: number): number {
    PLACEHOLDER_STICKY_RE.lastIndex = start;
    const match = PLACEHOLDER_STICKY_RE.exec(text);
    return match ? start + match[0].length : -1;
}

/** The text between placeholders: `a[REDACTED]b` -> ['a', 'b']. One entry more
 *  than there are placeholders; empty strings kept. */
export function literalSegments(text: string): string[] {
    return text.split(PLACEHOLDER_GLOBAL_RE);
}
