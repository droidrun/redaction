/**
 * regex-rule — rules that are one portable pattern (key formats, URL userinfo,
 * cookie lines) and their post-filters. A rule with `notBefore`/`notAfter` only
 * counts a match whose neighbours are not of those classes; a refused match
 * resumes the search one code unit after its start (exact for the fixed-length
 * patterns that use it). Each `prepare…` compiles once and returns the scanner.
 */
import { charTest, compile, containsTest, foldLower, type Range } from '../portable.js';
import { guardedRunEnd, runClasses } from './guarded-run.js';
import { isIpv6 } from './ipv6.js';
import { isPlaceholderValue } from './placeholder-value.js';
import { wordBefore } from './word-before.js';
import type { Rule } from '../spec.js';

export type Scanner = (text: string) => Range[];

/** A range a pattern found and where the whole match began and ended (the group can be smaller). */
type Candidate = { range: Range; matchStart: number; matchEnd: number };

type Filter = {
    requireClass?: string;
    requireLiteral?: string;
    dropPlaceholder?: boolean;
    ignoreEquals?: string[];
    ignoreSuffixes?: string[];
    ignoreAfterWords?: string[];
    afterGapClass?: string;
    ignoreBeforeClass?: string;
    ignoreAfterClass?: string;
    check?: string;
    minColons?: number;
};
type RegexRule = Rule &
    Filter & {
        pattern: string;
        group?: number;
        notBefore?: string;
        notAfter?: string;
    };
type CookieRule = Rule & Filter & { prefix: string; plainChar: string; escapeStop: string };

/** The named checks a `regex` rule may ask for (SPEC 5.8); an unknown name stops the package at load. */
function prepareCheck(filter: Filter): (value: string) => boolean {
    if (filter.check === undefined) return () => true;
    if (filter.check === 'ipv6') return (value) => isIpv6(value, filter.minColons ?? 0);
    throw new Error('unknown check in the spec');
}

/** True when the word before the match is one of the listed words (SPEC 4.1 `ignoreAfterWords`). */
function prepareContext(filter: Filter): (text: string, matchStart: number) => boolean {
    const words = filter.ignoreAfterWords;
    if (words === undefined) return () => false;
    const isGap = filter.afterGapClass === undefined ? () => false : charTest(filter.afterGapClass);
    return (text, matchStart) => words.includes(wordBefore(text, matchStart, isGap));
}

/** True when the lower-cased candidate ends with one of the listed literals (SPEC 4.1 `ignoreSuffixes`). */
function prepareSuffixes(filter: Filter): (value: string) => boolean {
    const suffixes = filter.ignoreSuffixes;
    if (suffixes === undefined) return () => false;
    return (value) => {
        const lower = foldLower(value);
        return suffixes.some((suffix) => lower.endsWith(suffix));
    };
}

/** True when the unit before the whole match is in `ignoreBeforeClass` or the unit after it is in
 *  `ignoreAfterClass` (SPEC 4.1): the match is a piece of something longer. */
function prepareEdges(filter: Filter): (text: string, matchStart: number, matchEnd: number) => boolean {
    const before = filter.ignoreBeforeClass;
    const after = filter.ignoreAfterClass;
    const blocksBefore = before === undefined ? () => false : charTest(before);
    const blocksAfter = after === undefined ? () => false : charTest(after);
    return (text, matchStart, matchEnd) => {
        if (matchStart > 0 && blocksBefore(text[matchStart - 1] as string)) return true;
        return matchEnd < text.length && blocksAfter(text[matchEnd] as string);
    };
}

function prepareFilter(filter: Filter): (text: string, candidate: Candidate) => boolean {
    const hasClass = filter.requireClass === undefined ? () => true : containsTest(filter.requireClass);
    const passesCheck = prepareCheck(filter);
    const hasIgnoredSuffix = prepareSuffixes(filter);
    const hasIgnoredContext = prepareContext(filter);
    const isPiece = prepareEdges(filter);
    return (text, { range: [start, end], matchStart, matchEnd }) => {
        const value = text.slice(start, end);
        if (!hasClass(value)) return false;
        if (filter.requireLiteral !== undefined && !value.includes(filter.requireLiteral)) return false;
        if (filter.ignoreEquals?.includes(value) === true) return false;
        if (hasIgnoredSuffix(value)) return false;
        if (hasIgnoredContext(text, matchStart)) return false;
        if (isPiece(text, matchStart, matchEnd)) return false;
        if (!passesCheck(value)) return false;
        return !(filter.dropPlaceholder === true && isPlaceholderValue(text, start, end));
    };
}

function prepareGuarded(rule: RegexRule): (text: string) => Candidate[] {
    const pattern = compile(rule.pattern, 'g');
    const blocksBefore = rule.notBefore === undefined ? () => false : charTest(rule.notBefore);
    const blocksAfter = rule.notAfter === undefined ? () => false : charTest(rule.notAfter);
    return (text) => {
        const found: Candidate[] = [];
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
            found.push({ range: [start, end], matchStart: start, matchEnd: end });
        }
        return found;
    };
}

function prepareGroup(rule: RegexRule): (text: string) => Candidate[] {
    const pattern = compile(rule.pattern, 'gd');
    const group = rule.group ?? 0;
    return (text) => {
        const found: Candidate[] = [];
        for (const match of text.matchAll(pattern)) {
            const range = match.indices?.[group];
            const matchEnd = match.index + match[0].length;
            if (range) found.push({ range: [range[0], range[1]], matchStart: match.index, matchEnd });
        }
        return found;
    };
}

export function prepareRegexRule(rule: RegexRule): Scanner {
    const hasGuard = rule.notBefore !== undefined || rule.notAfter !== undefined;
    const scan = hasGuard ? prepareGuarded(rule) : prepareGroup(rule);
    const passes = prepareFilter(rule);
    return (text) =>
        scan(text)
            .filter((candidate) => passes(text, candidate))
            .map((candidate) => candidate.range);
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
            const candidate = { range: [start, end] as Range, matchStart: match.index, matchEnd: end };
            if (passes(text, candidate)) ranges.push([start, end]);
        }
        return ranges;
    };
}
