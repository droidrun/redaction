/**
 * regex-rule — rules that are one portable pattern (key formats, URL userinfo,
 * cookie lines) and their post-filters. A rule with `notBefore`/`notAfter` only
 * counts a match whose neighbours are not of those classes; a refused match
 * resumes the search one code unit after its start (exact for the fixed-length
 * patterns that use it). Each `prepare…` compiles once and returns the scanner.
 */
import { charTest, compile, containsTest, type Range } from '../portable.js';
import { guardedRunEnd, runClasses } from './guarded-run.js';
import { isPlaceholderValue } from './placeholder-value.js';
import type { Rule } from '../spec.js';

export type Scanner = (text: string) => Range[];

type Filter = { requireClass?: string; requireLiteral?: string; dropPlaceholder?: boolean };
type RegexRule = Rule &
    Filter & {
        pattern: string;
        group?: number;
        notBefore?: string;
        notAfter?: string;
    };
type CookieRule = Rule & Filter & { prefix: string; plainChar: string; escapeStop: string };

function prepareFilter(filter: Filter): (text: string, range: Range) => boolean {
    const hasClass = filter.requireClass === undefined ? () => true : containsTest(filter.requireClass);
    return (text, [start, end]) => {
        const value = text.slice(start, end);
        if (!hasClass(value)) return false;
        if (filter.requireLiteral !== undefined && !value.includes(filter.requireLiteral)) return false;
        return !(filter.dropPlaceholder === true && isPlaceholderValue(text, start, end));
    };
}

function prepareGuarded(rule: RegexRule): Scanner {
    const pattern = compile(rule.pattern, 'g');
    const blocksBefore = rule.notBefore === undefined ? () => false : charTest(rule.notBefore);
    const blocksAfter = rule.notAfter === undefined ? () => false : charTest(rule.notAfter);
    return (text) => {
        const ranges: Range[] = [];
        pattern.lastIndex = 0;
        for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
            const start = match.index;
            const end = start + match[0].length;
            const before = start > 0 ? (text[start - 1] as string) : undefined;
            const after = end < text.length ? (text[end] as string) : undefined;
            const blocked =
                (before !== undefined && blocksBefore(before)) || (after !== undefined && blocksAfter(after));
            if (blocked) {
                pattern.lastIndex = start + 1;
                continue;
            }
            ranges.push([start, end]);
        }
        return ranges;
    };
}

function prepareGroup(rule: RegexRule): Scanner {
    const pattern = compile(rule.pattern, 'gd');
    const group = rule.group ?? 0;
    return (text) => {
        const ranges: Range[] = [];
        for (const match of text.matchAll(pattern)) {
            const range = match.indices?.[group];
            if (range) ranges.push([range[0], range[1]]);
        }
        return ranges;
    };
}

export function prepareRegexRule(rule: RegexRule): Scanner {
    const hasGuard = rule.notBefore !== undefined || rule.notAfter !== undefined;
    const scan = hasGuard ? prepareGuarded(rule) : prepareGroup(rule);
    const passes = prepareFilter(rule);
    return (text) => scan(text).filter((range) => passes(text, range));
}

/** `Cookie: a=b; c=d` lines: the value runs to the end of the line (or an escaped quote/newline). */
export function prepareCookieLines(rule: CookieRule): Scanner {
    const pattern = compile(rule.prefix, 'g');
    const classes = runClasses(rule);
    const passes = prepareFilter(rule);
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
            if (passes(text, [start, end])) ranges.push([start, end]);
        }
        return ranges;
    };
}
