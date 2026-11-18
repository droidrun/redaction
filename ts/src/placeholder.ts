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
 * The grammar and the format parameters are the spec's (`placeholder`).
 */
import { compile } from './portable.js';
import { ALGORITHMS_SPEC, RULES_SPEC } from './spec.js';

const FORMAT = ALGORITHMS_SPEC.placeholder;

// TypeScript extension (SPEC section 13): the 0.1.1 `last4` form. It never changes what is detected.
/** A match of at least this many units gets a `:last4` suffix when `last4` is asked for. */
const LAST4_THRESHOLD = 16;
/** Brackets would end a placeholder early, so they are masked in the last four units. */
const LAST4_MASKED = ['[', ']'];

/** Strip the `@secretlint/secretlint-rule-` / `mobilerun-redaction/` noise so
 *  the marker stays compact — e.g. `@secretlint/secretlint-rule-aws` -> `aws`. */
export function shortenRuleId(ruleId: string): string {
    return FORMAT.stripPrefixes.reduce(
        (id, prefix) => (id.startsWith(prefix) ? id.slice(prefix.length) : id),
        ruleId,
    );
}

/** Brackets would end a placeholder early, so they are masked in the last4. */
function safeLast4(matched: string): string {
    return [...matched.slice(-4)].map((char) => (LAST4_MASKED.includes(char) ? '*' : char)).join('');
}

export function buildPlaceholder(ruleId: string, matched: string): string {
    const shortId = shortenRuleId(ruleId);
    if (matched.length >= LAST4_THRESHOLD) {
        return `${FORMAT.open}${shortId}:${safeLast4(matched)}${FORMAT.close}`;
    }
    return `${FORMAT.open}${shortId}${FORMAT.close}`;
}

/** The read/log form: `[REDACTED:<ruleId>]`, never a `:last4` suffix, so no
 *  character of a stored secret is exposed. This is what the sync path, the
 *  default async path and every read route emit. */
export function buildReadPlaceholder(ruleId: string): string {
    return `${FORMAT.open}${shortenRuleId(ruleId)}${FORMAT.close}`;
}

const PLACEHOLDER_PATTERN = RULES_SPEC.patterns.placeholder;
const ANCHORED = compile(PLACEHOLDER_PATTERN, 'y');

/** Matches a string that IS one placeholder (anchored): any of the three forms. */
export const PLACEHOLDER_RE = new RegExp(`^${compile(PLACEHOLDER_PATTERN).source}$`);

/** A placeholder anywhere in a string (not anchored, not global). Internal. */
export const PLACEHOLDER_ANYWHERE_RE = compile(PLACEHOLDER_PATTERN);

const PLACEHOLDER_GLOBAL_RE = compile(PLACEHOLDER_PATTERN, 'g');

/** End index of the placeholder starting exactly at `start`, or -1. */
export function placeholderEndAt(text: string, start: number): number {
    ANCHORED.lastIndex = start;
    const match = ANCHORED.exec(text);
    return match ? start + match[0].length : -1;
}

/** The text between placeholders: `a[REDACTED]b` -> ['a', 'b']. One entry more
 *  than there are placeholders; empty strings kept. */
export function literalSegments(text: string): string[] {
    return text.split(PLACEHOLDER_GLOBAL_RE);
}
