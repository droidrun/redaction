/**
 * generic-keyword-rule.ts — custom secretlint rule: `label: value` /
 * `label=value` pairs where the label looks like a credential and the value
 * has "evidence" of actually being secret material (not `password: undefined`
 * or a doc example).
 *
 * Only the VALUE is reported/redacted — the label stays untouched (matters
 * for placeholders like `[REDACTED:generic-keyword]` reading sensibly next
 * to the original `password:` prefix).
 *
 * Bounded quantifiers only (`{8,}` with a negated character class, no nested
 * repetition) — safe against ReDoS on adversarial input.
 */
import type { SecretLintRuleCreator } from '@secretlint/types';
import { PLACEHOLDER_RE } from '../placeholder.js';

// password|passwd|pwd|secret|token|api[_-]?key; a few more
// common aliases folded in since they're the same threat shape and the
// negative corpus already has to cover them (accessKey, clientSecret,
// privateKey, credential(s), authorization/bearer).
//
// The keyword may be matched as a SUFFIX of a wider identifier (an OPTIONAL
// `(?:[A-Za-z][A-Za-z0-9_-]*?)?` prefix) rather than behind a bare `\b` —
// `\b` sits between a word char and a non-word char, so it does NOT match
// between `_`/camelCase-adjacent letters and the keyword: `session_token:`
// or `clientSecret:` would otherwise be silently missed entirely (verified
// during implementation — a real false-negative, not just a tuning nit). The
// prefix group is wrapped in `(?:...)?` so a bare `password:`/`token:` (no
// prefix at all) still matches too. Lazy, single-level quantifiers only (no
// nesting) — still linear-time safe.
//
// `d` flag (hasIndices) so `match.indices[2]` gives the VALUE group's exact
// [start, end] directly — no fragile manual offset reconstruction needed to
// report a range that covers only the value, not the label/quotes.
const KEYWORD_VALUE_PATTERN = new RegExp(
    String.raw`\b(?:[A-Za-z][A-Za-z0-9_-]*?)?(?:password|passwd|pwd|secret|token|api[_-]?key|` +
    String.raw`access[_-]?key|client[_-]?secret|private[_-]?key|credentials?|authorization|bearer)` +
    String.raw`[A-Za-z0-9_-]*?\s*[:=]\s*(["']?)([^\s"',;]{8,})\1`,
    'gdi',
);

const TRIVIAL_VALUES = new Set([
    'undefined', 'null', 'changeme', 'example', 'placeholder', 'password', 'secret', 'token',
]);

function isTrivialValue(raw: string): boolean {
    const v = raw.trim().toLowerCase();
    if (TRIVIAL_VALUES.has(v)) return true;
    if (/^x+$/i.test(v)) return true; // "xxxxxxxx"
    if (/^\*+$/.test(v)) return true; // "********"
    if (/^<.*>$/.test(v)) return true; // "<placeholder>"
    if (/^\{.*\}$/.test(v)) return true; // "{{secret}}" template placeholder
    return false;
}

/** Shannon entropy in bits/char — a fallback signal for values that don't mix
 *  character classes but are still clearly high-entropy (e.g. a long
 *  all-lowercase-plus-digits token). */
function shannonEntropy(s: string): number {
    const freq = new Map<string, number>();
    for (const ch of s) {
        freq.set(ch, (freq.get(ch) ?? 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
        const p = count / s.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

// Tuned empirically (see redact-text.test.ts's negative corpus): natural
// English-ish doc placeholders ("your_api_key_here" ~3.29,
// "REPLACE_ME_TOKEN" ~3.38 bits/char) sit just below this; a real passphrase
// example ("correct-horse-battery-staple" ~3.50) and any password with
// meaningful character variety sit at or above it. Not a hard boundary —
// entropy-based heuristics inherently have a gray zone; the class-mix path
// (>=3 classes) is the primary, higher-precision signal and covers most
// realistic secrets on its own.
const ENTROPY_THRESHOLD = 3.4;

/**
 * "Value evidence": at least 3 of {lower, upper, digit, special} character
 * classes present, OR high enough Shannon entropy. Deny-listed trivial
 * values (and anything that's already one of OUR OWN placeholders — the
 * idempotence guard) never count as evidence regardless.
 *
 * Threshold is 3 classes, not 2: common doc/placeholder conventions
 * (`your_api_key_here`, `REPLACE_ME_TOKEN`) are lowercase-or-uppercase +
 * underscore — exactly 2 classes — and would otherwise false-positive on
 * every README. A real secret with meaningful entropy either mixes 3+
 * classes (most generated keys do) or clears the entropy fallback even at
 * 1-2 classes (e.g. a long lowercase-alnum-only token).
 */
function hasValueEvidence(raw: string): boolean {
    const unquoted = raw.replace(/^['"]|['"]$/g, '');
    if (PLACEHOLDER_RE.test(unquoted)) return false;
    if (isTrivialValue(unquoted)) return false;
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(unquoted)).length;
    if (classes >= 3) return true;
    return shannonEntropy(unquoted) >= ENTROPY_THRESHOLD;
}

const MESSAGES = {
    KEYWORD_VALUE: {
        en: () => 'found a credential-looking key/value pair',
    },
};

export const genericKeywordRule: SecretLintRuleCreator = {
    messages: MESSAGES,
    meta: {
        id: 'mobilerun-redaction/generic-keyword',
        type: 'scanner',
        recommended: true,
        supportedContentTypes: ['text'],
    },
    create(context) {
        const t = context.createTranslator(MESSAGES);
        return {
            file(source) {
                for (const match of source.content.matchAll(KEYWORD_VALUE_PATTERN)) {
                    const value = match[2] ?? '';
                    if (!hasValueEvidence(value)) continue;
                    const valueRange = match.indices?.[2];
                    if (!valueRange) continue;
                    context.report({
                        message: t('KEYWORD_VALUE'),
                        range: valueRange,
                    });
                }
            },
        };
    },
};
