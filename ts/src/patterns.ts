/**
 * patterns.ts — the key-format and keyword rule definitions behind
 * `sync-rules.ts`, which is the one rule source of both entry points (the
 * async path adds the upstream secretlint scanners on top).
 *
 * Bounded quantifiers wherever a pattern could otherwise rescan the same run
 * of characters from many start positions.
 */
import { PLACEHOLDER_RE, placeholderEndAt } from './placeholder.js';

export const JWT_PATTERN = /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/g;

/** `AIza` + exactly 35 chars of the key alphabet. Lookarounds, not `\b`: the
 *  alphabet includes `-`, so a key ending in `-` has no word boundary. */
export const GCP_API_KEY_PATTERN = /(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g;

/** `xai-` + exactly 80 chars (TruffleHog's API-verified shape). */
export const XAI_API_KEY_PATTERN = /\bxai-[0-9a-zA-Z_]{80}\b/g;

// Credential keywords. The keyword may sit anywhere in an identifier
// (`session_token:`, `clientSecret:`), so the pattern is NOT anchored on the
// left: the engine finds the keyword itself, and the work per candidate is
// bounded (tail 64, value 256 + a linear extension) instead of a lazy prefix
// retried at every word start. A closing quote of a JSON key may sit between
// the keyword and the colon, also backslash-escaped (`{\"password\":\"x\"}`,
// any number of escaping layers).
//
// `d` flag (hasIndices) so `match.indices[1]` is the VALUE group's exact range.
const KEYWORDS =
    String.raw`password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|` +
    String.raw`private[_-]?key|credentials?|authorization|bearer`;
const ESCAPED_QUOTE = String.raw`(?:\\*["'])`;
/** Longest value captured per candidate; a longer run is extended once accepted. */
const VALUE_WINDOW = 256;
/** One character of an unquoted value: not whitespace, quote, `,`, `;`, and not
 *  a backslash that begins an escape (`\"`, `\\`). */
const VALUE_CHAR = String.raw`(?:[^\s"',;\\]|\\(?![\\"']))`;
export const KEYWORD_VALUE_PATTERN = new RegExp(
    String.raw`(?:${KEYWORDS})[A-Za-z0-9_-]{0,64}?${ESCAPED_QUOTE}?\s*[:=]\s*${ESCAPED_QUOTE}?` +
    String.raw`(${VALUE_CHAR}{8,${VALUE_WINDOW}})`,
    'gdi',
);
const VALUE_RUN = new RegExp(`${VALUE_CHAR}*`, 'y');

/** End of the unquoted value run starting at `from` (linear, unbounded). */
export function valueRunEnd(text: string, from: number): number {
    VALUE_RUN.lastIndex = from;
    const match = VALUE_RUN.exec(text);
    return match ? from + match[0].length : from;
}

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

const IDENT_CHAR = /[A-Za-z0-9_%-]/;

/** Start of the identifier that holds the keyword at `keywordStart` (at most 64 back). */
function labelStart(content: string, keywordStart: number): number {
    let start = keywordStart;
    while (start > 0 && keywordStart - start < 64 && IDENT_CHAR.test(content[start - 1] ?? '')) {
        start -= 1;
    }
    return start;
}

/** Inside a URL query string (`?token=…&x=1`) a value ends at the next `&`.
 *  `labelStart` is where the `label=value` identifier began. */
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
 *  Linear: every attempt does bounded work and scanning resumes at the START
 *  of the rejected value (not after it, so a value that is itself a label —
 *  `password : session_token: <secret>` — does not hide the pair behind it, and
 *  not one character after the label, which made `a_token=a_token=…` quadratic).
 *  A value longer than the 256-character capture is extended to its whole run
 *  (fail closed: no suffix of a long secret is left behind). */
export function keywordValueRanges(content: string): Array<[number, number]> {
    const ranges: Array<[number, number]> = [];
    const pattern = new RegExp(KEYWORD_VALUE_PATTERN);
    for (let match = pattern.exec(content); match !== null; match = pattern.exec(content)) {
        const valueRange = match.indices?.[1];
        if (!valueRange) continue;
        const [start, end] = trimQueryValue(content, labelStart(content, match.index), valueRange);
        const isPlaceholder = placeholderEndAt(content, start) >= end;
        const accepted = end > start && !isPlaceholder && hasValueEvidence(content.slice(start, end));
        if (!accepted) {
            pattern.lastIndex = valueRange[0];
            continue;
        }
        // Extend a value that filled the capture window to its whole run, and only now
        // (an extension per rejected candidate would rescan the run each time).
        const full = end - start === VALUE_WINDOW ? valueRunEnd(content, end) : end;
        ranges.push([start, full]);
        pattern.lastIndex = Math.max(full, valueRange[0]);
    }
    return ranges;
}
