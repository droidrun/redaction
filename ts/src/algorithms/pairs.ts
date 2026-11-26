/**
 * pairs — `label: value` rules for credential-shaped labels:
 *
 *  - keyword pairs: a credential keyword anywhere in an identifier, a value of at
 *    least `minValueLength` characters that has evidence of being secret;
 *  - quoted pairs: the value sits in quotes (may hold spaces, escaped quotes);
 *  - unquoted pairs: the value ends at whitespace or a delimiter.
 *
 * Linear: every attempt does bounded work and scanning resumes at the START of a
 * rejected value (so a value that is itself a label — `password : session_token: x` —
 * does not hide the pair behind it). Each `prepare…` compiles once.
 */
import { charTest, compile, foldLower, type CharTest, type Range } from '../portable.js';
import { hasValueEvidence, isDocPlaceholder, isTrivialValue } from './evidence.js';
import { guardedRunEnd, runClasses, type RunClasses } from './guarded-run.js';
import { isPlaceholderValue } from './placeholder-value.js';
import { labelStart, trimQueryValue } from './query-value.js';
import { keyVerdict, type KeyVerdict } from '../key-names.js';
import { placeholderEndAt } from '../placeholder.js';
import type { Scanner } from './regex-rule.js';
import { RULES_SPEC, type Rule } from '../spec.js';

type KeywordRule = Rule & {
    prefix: string;
    plainChar: string;
    escapeStop: string;
    minValueLength: number;
    window: number;
    identChar: string;
    labelLookback: number;
};
type QuotedRule = Rule & { label: string; valueLimit: number };
type UnquotedRule = Rule & { prefix: string; plainChar: string; escapeStop: string };
type KeyPairsRule = Rule & {
    label: string;
    valueLimit: number;
    plainChar: string;
    escapeStop: string;
    identChar: string;
    labelLookback: number;
    keyChar: string;
    keyMax: number;
    gapClass: string;
    quoteChar: string;
    digitClass: string;
    standInMinLength: number;
    keptMaxLength: number;
    schemeWords: string[];
    schemeKeys: string[];
};

export function prepareKeywordPairs(rule: KeywordRule): Scanner {
    const pattern = compile(rule.prefix, 'g');
    const classes = runClasses(rule);
    const isIdent = charTest(rule.identChar);
    return (text) => {
        const ranges: Range[] = [];
        pattern.lastIndex = 0;
        for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
            const valueStart = match.index + match[0].length;
            const valueEnd = guardedRunEnd(text, valueStart, classes, rule.window);
            if (valueEnd - valueStart < rule.minValueLength) {
                pattern.lastIndex = match.index + 1;
                continue;
            }
            const label = labelStart(text, match.index, isIdent, rule.labelLookback);
            const [start, end] = trimQueryValue(text, label, [valueStart, valueEnd]);
            const markerEnd = placeholderEndAt(text, start);
            const isPlaceholder = markerEnd >= end || (markerEnd === end - 1 && text[markerEnd] === '}');
            const accepted = end > start && !isPlaceholder && hasValueEvidence(text.slice(start, end));
            if (!accepted) {
                pattern.lastIndex = valueStart;
                continue;
            }
            // A value that filled the window runs on to the end of its run (no suffix of a
            // long secret is left behind); only now, so a rejected candidate never rescans it.
            const full = end - start === rule.window ? guardedRunEnd(text, end, classes) : end;
            ranges.push([start, full]);
            pattern.lastIndex = Math.max(full, valueStart);
        }
        return ranges;
    };
}

/** Pair values: not empty, not a placeholder, not a doc mask or stand-in. */
function realPairValues(text: string, ranges: Range[]): Range[] {
    return ranges.filter(([start, end]) => {
        if (end <= start || isPlaceholderValue(text, start, end)) return false;
        const value = text.slice(start, end);
        return !isTrivialValue(value) && !isDocPlaceholder(value);
    });
}

/** Closing quote of a value that opened at `from`, or -1. `layers` is the number of
 *  escape backslashes before the opening quote (escaped JSON). */
function closingQuote(text: string, from: number, quote: string, layers: number, limit: number): number {
    for (let i = from; i < limit; i++) {
        if (text[i] !== quote) continue;
        let run = 0;
        while (i - run - 1 >= from && text[i - run - 1] === '\\') run += 1;
        const closes = layers === 0 ? run % 2 === 0 : run === layers;
        if (closes) return i - run;
    }
    return -1;
}

/** An unterminated or over-long quoted value fails closed: redacted to the end of the text. */
export function prepareQuotedPairs(rule: QuotedRule): Scanner {
    const pattern = compile(rule.label, 'g');
    return (text) => {
        const ranges: Range[] = [];
        pattern.lastIndex = 0;
        for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
            const layers = (match[1] ?? '').length;
            const quote = match[2] ?? '"';
            const from = pattern.lastIndex;
            const limit = Math.min(text.length, from + rule.valueLimit);
            const close = closingQuote(text, from, quote, layers, limit);
            if (close === -1) {
                if (from < text.length) ranges.push([from, text.length]);
                break;
            }
            ranges.push([from, close]);
            pattern.lastIndex = close;
        }
        return realPairValues(text, ranges);
    };
}

export function prepareUnquotedPairs(rule: UnquotedRule): Scanner {
    const pattern = compile(rule.prefix, 'g');
    const classes = runClasses(rule);
    return (text) => {
        const ranges: Range[] = [];
        pattern.lastIndex = 0;
        for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
            const start = match.index + match[0].length;
            const end = guardedRunEnd(text, start, classes);
            if (end === start) {
                pattern.lastIndex = match.index + 1;
                continue;
            }
            pattern.lastIndex = end;
            ranges.push(trimQueryValue(text, match.index, [start, end]));
        }
        return realPairValues(text, ranges);
    };
}

type KeptTest = (key: string, value: string, verdict: KeyVerdict) => boolean;

/** True for a value that stays under a key whose verdict says secret: a stand-in, a documentation
 *  placeholder, a status word, an authorization scheme word under an authorization key, and (under a `string`
 *  verdict) a plain number. A value longer than `keptMaxLength` is never kept: the tests would cost the whole
 *  run at every pair. */
function prepareKeptValue(rule: KeyPairsRule): KeptTest {
    const isDigit = charTest(rule.digitClass);
    const statusWords = new Set(RULES_SPEC.statusWords);
    const schemeWords = new Set(rule.schemeWords);
    const schemeKeys = new Set(rule.schemeKeys);
    return (key, value, verdict) => {
        const isStandIn = value.length >= rule.standInMinLength && isTrivialValue(value);
        if (isStandIn || isDocPlaceholder(value)) return true;
        const word = foldLower(value.trim());
        if (statusWords.has(word)) return true;
        if (schemeWords.has(word) && schemeKeys.has(foldLower(key).replace(/[-_]/g, ''))) return true;
        return verdict === 'string' && [...value].every(isDigit);
    };
}

type KeyClasses = { gap: CharTest; quote: CharTest; key: CharTest };

const isBackslash = (unit: string): boolean => unit === '\\';

/** The key that stands before the separator at `at`: spaces, an optional (escaped) quote, then up to `keyMax`
 *  units of `keyChar`. `undefined` when no key stands there. */
function keyBefore(text: string, at: number, classes: KeyClasses, keyMax: number): Range | undefined {
    let end = labelStart(text, at, classes.gap, Number.POSITIVE_INFINITY);
    if (end > 0 && classes.quote(text[end - 1] as string)) {
        end = labelStart(text, end - 1, isBackslash, Number.POSITIVE_INFINITY);
    }
    const start = labelStart(text, end, classes.key, keyMax);
    return start === end ? undefined : [start, end];
}

/** The end of a run is the same from every start inside it: the last run measured is remembered, so a text
 *  of many pairs in one long run is measured once. */
function rememberedRunEnd(text: string, classes: RunClasses): (from: number) => number {
    let low = 0;
    let high = 0;
    return (from) => {
        if (from >= low && from < high) return high;
        low = from;
        high = guardedRunEnd(text, from, classes);
        return high;
    };
}

/** The first `&` at or after `from` (or -1), remembered: `from` only grows within one scan. */
function rememberedAmpersand(text: string): (from: number) => number {
    let found = -2;
    return (from) => {
        if (found === -2 || (found !== -1 && found < from)) found = text.indexOf('&', from);
        return found;
    };
}

/** `trimQueryValue` (SPEC 5.3) for a value inside a URL query, with the next `&` remembered: the search of a
 *  text of many pairs inside one long run (`?token=` repeated) would otherwise read the run at every pair. */
function queryValueEnd(text: string, next: (from: number) => number, label: number, value: Range): number {
    const before = text[label - 1];
    if (before !== '?' && before !== '&') return value[1];
    const amp = next(value[0]);
    return amp === -1 || amp >= value[1] ? value[1] : amp;
}

/** Where the value of a quoted pair ends, or -1 when it has no closing quote within `valueLimit`. */
function quotedValueEnd(text: string, from: number, match: RegExpExecArray, rule: KeyPairsRule): number {
    const layers = (match[1] ?? '').length;
    const limit = Math.min(text.length, from + rule.valueLimit);
    return closingQuote(text, from, match[2] as string, layers, limit);
}

/**
 * `key: value` pairs decided by the key verdict of SPEC 6, the same one that decides JSON keys, added to the
 * quoted and unquoted pair rules in `strict`. The value is quoted (it may hold spaces and escaped quotes; one
 * without a closing quote fails closed to the end of the text and ends this scan) or runs to a delimiter and
 * never starts after a line break. A key without a verdict gives no range; after an unquoted value the search
 * resumes at the value, so a pair inside it is still found.
 */
export function prepareKeyPairs(rule: KeyPairsRule): Scanner {
    const pattern = compile(rule.label, 'g');
    const classes = runClasses(rule);
    const isKept = prepareKeptValue(rule);
    const isIdent = charTest(rule.identChar);
    const keyClasses = {
        gap: charTest(rule.gapClass),
        quote: charTest(rule.quoteChar),
        key: charTest(rule.keyChar),
    };
    return (text) => {
        const ranges: Range[] = [];
        const runEnd = rememberedRunEnd(text, classes);
        const nextAmp = rememberedAmpersand(text);
        pattern.lastIndex = 0;
        for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
            const key = keyBefore(text, match.index, keyClasses, rule.keyMax);
            const from = pattern.lastIndex;
            if (key === undefined) continue;
            const keyText = text.slice(key[0], key[1]);
            const verdict = keyVerdict(keyText);
            if (verdict === 'none') continue;
            const isQuoted = match[2] !== undefined;
            const close = isQuoted ? quotedValueEnd(text, from, match, rule) : -1;
            if (isQuoted && close === -1) {
                if (from < text.length && !isPlaceholderValue(text, from, text.length)) {
                    ranges.push([from, text.length]);
                }
                break;
            }
            const end = isQuoted ? close : runEnd(from);
            if (end === from && !isQuoted) {
                pattern.lastIndex = match.index + 1;
                continue;
            }
            const label = labelStart(text, key[0], isIdent, rule.labelLookback);
            const start = from;
            const stop = isQuoted ? end : queryValueEnd(text, nextAmp, label, [from, end]);
            const isSecret = stop > start && !isPlaceholderValue(text, start, stop);
            const isShort = stop - start <= rule.keptMaxLength;
            if (!isSecret || (isShort && isKept(keyText, text.slice(start, stop), verdict))) continue;
            ranges.push([start, stop]);
            pattern.lastIndex = isQuoted ? Math.max(stop, from) : from;
        }
        return ranges;
    };
}
