/**
 * patterns.ts — the regex rule definitions that BOTH the secretlint rules
 * (`rules/*.ts`, async path) and the sync path (`sync-rules.ts`) use. One
 * copy of every pattern; the rule files only wrap them for secretlint.
 *
 * Bounded quantifiers wherever a pattern could otherwise rescan the same run
 * of characters from many start positions.
 */
import { PLACEHOLDER_RE } from './placeholder.js';

export const JWT_PATTERN = /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/g;

/** `AIza` + exactly 35 chars of the key alphabet. Lookarounds, not `\b`: the
 *  alphabet includes `-`, so a key ending in `-` has no word boundary. */
export const GCP_API_KEY_PATTERN = /(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g;

/** `xai-` + exactly 80 chars (TruffleHog's API-verified shape). */
export const XAI_API_KEY_PATTERN = /\bxai-[0-9a-zA-Z_]{80}\b/g;

// password|passwd|pwd|secret|token|api[_-]?key; a few more common aliases
// (accessKey, clientSecret, privateKey, credential(s), authorization/bearer).
//
// The keyword may be a SUFFIX of a wider identifier (`session_token:`,
// `clientSecret:`), so an optional lazy prefix is used instead of a bare `\b`.
// The prefix and the tail after the keyword are bounded (64) so a long
// hyphenated run cannot make every `\b` rescan the whole run. A closing quote
// of a JSON key (`"password": "…"`) may sit between the keyword and the colon.
//
// `d` flag (hasIndices) so `match.indices[2]` is the VALUE group's exact range.
const KEYWORDS =
    String.raw`password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|` +
    String.raw`private[_-]?key|credentials?|authorization|bearer`;
export const KEYWORD_VALUE_PATTERN = new RegExp(
    String.raw`\b(?:[A-Za-z][A-Za-z0-9_-]{0,63}?)?(?:${KEYWORDS})[A-Za-z0-9_-]{0,64}?["']?\s*[:=]\s*` +
    String.raw`(["']?)([^\s"',;]{8,})\1`,
    'gdi',
);

const TRIVIAL_VALUES = new Set([
    'undefined', 'null', 'changeme', 'example', 'placeholder', 'password', 'secret', 'token',
]);

export function isTrivialValue(raw: string): boolean {
    const v = raw.trim().toLowerCase();
    if (TRIVIAL_VALUES.has(v)) return true;
    if (/^x+$/i.test(v)) return true; // "xxxxxxxx"
    if (/^\*+$/.test(v)) return true; // "********"
    if (/^<.*>$/.test(v)) return true; // "<placeholder>"
    if (/^\{.*\}$/.test(v)) return true; // "{{secret}}" template placeholder
    return false;
}

/** Documentation-style stand-ins (`your_api_key_here`, `REPLACE_ME_TOKEN`). */
export function isDocPlaceholder(raw: string): boolean {
    return /^(?:your|my|the|replace|insert|example|dummy|sample)[_-]|[_-]here$/i.test(raw.trim());
}

/** Shannon entropy in bits/char — a fallback signal for values that don't mix
 *  character classes but are still clearly high-entropy. */
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
// example ("correct-horse-battery-staple" ~3.50) sits at or above it.
const ENTROPY_THRESHOLD = 3.4;

/**
 * "Value evidence": at least 3 of {lower, upper, digit, special} character
 * classes present, OR high enough Shannon entropy. Deny-listed trivial values
 * (and anything that is already one of OUR OWN placeholders — the idempotence
 * guard) never count as evidence. Threshold is 3 classes, not 2, because
 * `your_api_key_here` / `REPLACE_ME_TOKEN` are exactly 2 classes.
 */
export function hasValueEvidence(raw: string): boolean {
    const unquoted = raw.replace(/^['"]|['"]$/g, '');
    if (PLACEHOLDER_RE.test(unquoted)) return false;
    if (isTrivialValue(unquoted)) return false;
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(unquoted)).length;
    if (classes >= 3) return true;
    return shannonEntropy(unquoted) >= ENTROPY_THRESHOLD;
}

/** Inside a URL query string (`?token=…&x=1`) a value ends at the next `&`.
 *  `labelStart` is where the `label=value` match began. */
export function trimQueryValue(
    content: string,
    labelStart: number,
    range: readonly [number, number],
): [number, number] {
    const before = content[labelStart - 1];
    if (before !== '?' && before !== '&') return [range[0], range[1]];
    const ampersand = content.indexOf('&', range[0]);
    return ampersand !== -1 && ampersand < range[1] ? [range[0], ampersand] : [range[0], range[1]];
}

/** Value ranges of every `label: value` pair whose label is credential-shaped
 *  and whose value has evidence of being secret material.
 *
 *  A candidate that fails the evidence test is not consumed: scanning resumes
 *  one character after its start, so a value that is itself a label
 *  (`password : session_token: <secret>`) does not hide the pair behind it. */
export function keywordValueRanges(content: string): Array<[number, number]> {
    const ranges: Array<[number, number]> = [];
    const pattern = new RegExp(KEYWORD_VALUE_PATTERN);
    for (let match = pattern.exec(content); match !== null; match = pattern.exec(content)) {
        const valueRange = match.indices?.[2];
        const [start, end] = valueRange ? trimQueryValue(content, match.index, valueRange) : [0, 0];
        if (end > start && hasValueEvidence(content.slice(start, end))) {
            ranges.push([start, end]);
            continue;
        }
        pattern.lastIndex = match.index + 1;
    }
    return ranges;
}
