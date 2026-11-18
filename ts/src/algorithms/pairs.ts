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
import { charTest, compile, type Range } from '../portable.js';
import { hasValueEvidence, isDocPlaceholder, isTrivialValue } from './evidence.js';
import { guardedRunEnd, runClasses } from './guarded-run.js';
import { isPlaceholderValue } from './placeholder-value.js';
import { labelStart, trimQueryValue } from './query-value.js';
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
