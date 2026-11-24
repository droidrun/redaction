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
import type { Rule } from '../spec.js';

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
    statusWords: string[];
    schemeWords: string[];
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
            const isPlaceholder = placeholderEndAt(text, start) >= end;
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

/** The value of a `key = value` pair that the key verdict makes secret, or none: a stand-in, a documentation
 *  placeholder, a status or scheme word, and (under a `string` verdict) a plain number stay. */
function prepareKeptValue(rule: KeyPairsRule): (value: string, verdict: KeyVerdict) => boolean {
    const isDigit = charTest(rule.digitClass);
    const keptWords = new Set([...rule.statusWords, ...rule.schemeWords]);
    return (value, verdict) => {
        const isStandIn = value.length >= rule.standInMinLength && isTrivialValue(value);
        if (isStandIn || isDocPlaceholder(value)) return true;
        if (keptWords.has(foldLower(value.trim()))) return true;
        return verdict === 'string' && [...value].every(isDigit);
    };
}

type KeyClasses = { gap: CharTest; quote: CharTest; key: CharTest };

/** The key that stands before the separator at `at`: spaces, an optional (escaped) quote, then up to `keyMax`
 *  units of `keyChar`. `undefined` when no key stands there. */
function keyBefore(text: string, at: number, classes: KeyClasses, keyMax: number): Range | undefined {
    let end = at;
    while (end > 0 && classes.gap(text[end - 1] as string)) end -= 1;
    if (end > 0 && classes.quote(text[end - 1] as string)) {
        end -= 1;
        while (end > 0 && text[end - 1] === '\\') end -= 1;
    }
    let start = end;
    while (start > 0 && end - start < keyMax && classes.key(text[start - 1] as string)) start -= 1;
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

/** Where the value of a pair ends and whether it is quoted. A quoted value ends at its closing quote; an
 *  unterminated or over-long one runs to the end of the text (fail closed). */
function pairValueEnd(
    text: string,
    from: number,
    match: RegExpExecArray,
    rule: KeyPairsRule,
    runEnd: (from: number) => number,
): number {
    const quote = match[2];
    if (quote === undefined) return runEnd(from);
    const layers = (match[1] ?? '').length;
    const limit = Math.min(text.length, from + rule.valueLimit);
    const close = closingQuote(text, from, quote, layers, limit);
    return close === -1 ? text.length : close;
}

/**
 * `key: value` pairs decided by the key verdict of SPEC 6, the same one that decides JSON keys: the strict
 * replacement of the quoted and unquoted pair rules. The value is quoted (it may hold spaces and escaped
 * quotes, and an unterminated or over-long one fails closed) or runs to a delimiter. A key without a verdict
 * gives no range and scanning resumes at its value, so a pair inside that value is still found.
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
        pattern.lastIndex = 0;
        for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
            const key = keyBefore(text, match.index, keyClasses, rule.keyMax);
            const from = pattern.lastIndex;
            if (key === undefined) continue;
            const verdict = keyVerdict(text.slice(key[0], key[1]));
            if (verdict === 'none') continue;
            const end = pairValueEnd(text, from, match, rule, runEnd);
            if (end === from && match[2] === undefined) {
                pattern.lastIndex = match.index + 1;
                continue;
            }
            const label = labelStart(text, key[0], isIdent, rule.labelLookback);
            const isQuoted = match[2] !== undefined;
            const [start, stop] = isQuoted ? [from, end] : trimQueryValue(text, label, [from, end]);
            const isSecret = stop > start && !isPlaceholderValue(text, start, stop);
            if (!isSecret || isKept(text.slice(start, stop), verdict)) continue;
            ranges.push([start, stop]);
            pattern.lastIndex = Math.max(stop, from);
        }
        return ranges;
    };
}
