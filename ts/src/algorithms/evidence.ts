/**
 * evidence — "does this value look like secret material": the value-evidence
 * test (character classes or entropy), the trivial-value and the documentation
 * stand-in checks. Parameters are the spec's (`evidence`, `trivial`, `docPlaceholder`).
 */
import { containsTest, foldLower } from '../portable.js';
import { PLACEHOLDER_RE } from '../placeholder.js';
import { ALGORITHMS_SPEC } from '../spec.js';

const { evidence, trivial, docPlaceholder } = ALGORITHMS_SPEC;
const TRIVIAL_WORDS = new Set(trivial.words);
const CLASS_TESTS = evidence.classes.map(containsTest);
const INNER_UNIT = new RegExp(`^${trivial.wrapperInner}$`);
const DOC_SEPARATOR = new RegExp(`^${docPlaceholder.separator}$`);

/** Shannon entropy in bits per code point of `text`; the divisor is the UTF-16 length. */
function shannonEntropy(text: string): number {
    const frequencies = new Map<string, number>();
    for (const char of text) frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
    let entropy = 0;
    for (const count of frequencies.values()) {
        const probability = count / text.length;
        entropy -= probability * Math.log2(probability);
    }
    return entropy;
}

function trimWhitespace(raw: string): string {
    return raw.trim();
}

function isMask(value: string): boolean {
    return value.length > 0 && trivial.maskChars.some((mask) => [...value].every((char) => char === mask));
}

function isWrapped(value: string): boolean {
    return trivial.wrappers.some(([open, close]) => {
        const inner = value.slice(1, -1);
        const isWrapper =
            value.length >= 2 && value.startsWith(open as string) && value.endsWith(close as string);
        return isWrapper && [...inner].every((unit) => INNER_UNIT.test(unit));
    });
}

/** Deny-listed stand-ins: `null`, `changeme`, `xxxxxxxx`, `********`, `<placeholder>`, `{{secret}}`. */
export function isTrivialValue(raw: string): boolean {
    const value = foldLower(trimWhitespace(raw));
    return TRIVIAL_WORDS.has(value) || isMask(value) || isWrapped(value);
}

/** Documentation-style stand-ins (`your_api_key_here`, `REPLACE_ME_TOKEN`). */
export function isDocPlaceholder(raw: string): boolean {
    const value = foldLower(trimWhitespace(raw));
    const startsWithPrefix = docPlaceholder.prefixes.some((prefix) => {
        return value.startsWith(prefix) && DOC_SEPARATOR.test(value[prefix.length] ?? '');
    });
    const endsWithSuffix = docPlaceholder.suffixes.some((suffix) => {
        const at = value.length - suffix.length - 1;
        return at >= 0 && value.endsWith(suffix) && DOC_SEPARATOR.test(value[at] as string);
    });
    return startsWithPrefix || endsWithSuffix;
}

function stripQuotes(raw: string): string {
    const withoutLeading = evidence.quoteChars.includes(raw[0] ?? '\0') ? raw.slice(1) : raw;
    const last = withoutLeading[withoutLeading.length - 1] ?? '\0';
    return evidence.quoteChars.includes(last) ? withoutLeading.slice(0, -1) : withoutLeading;
}

/**
 * "Value evidence": at least `minClasses` of the character classes present, OR
 * high enough Shannon entropy. Deny-listed trivial values (and anything that is
 * already one of OUR OWN placeholders — the idempotence guard) never count.
 */
export function hasValueEvidence(raw: string): boolean {
    const unquoted = stripQuotes(raw);
    if (PLACEHOLDER_RE.test(unquoted)) return false;
    if (isTrivialValue(unquoted)) return false;
    const classes = CLASS_TESTS.filter((test) => test(unquoted)).length;
    if (classes >= evidence.minClasses) return true;
    return shannonEntropy(unquoted) >= evidence.entropyThreshold;
}
