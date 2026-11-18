/**
 * dotted-token — a token of `segments` runs of the segment class, the first after a
 * lead literal (`eyJ`), joined by the separator (`.`): `\blead SEG{min,} (. SEG{min,})* \b`.
 * Same matches as that regular expression, but linear: a start that fails memoizes the
 * run it examined, so the other starts inside that run are not rescanned (the plain
 * expression is quadratic on `eyJ-eyJ-eyJ-…`).
 *
 * The last segment takes the longest length of at least `minSegment` that ends on a word
 * boundary (a trailing `-` is left out, as the backtracking expression does).
 */
import { charTest, runEnd, type Range } from '../portable.js';
import type { Scanner } from './regex-rule.js';
import type { Rule } from '../spec.js';

type DottedRule = Rule & {
    lead: string;
    separator: string;
    segmentClass: string;
    wordClass: string;
    minSegment: number;
    segments: number;
};

type Match = { end: number } | { failedRunEnd: number };

export function prepareDottedToken(rule: DottedRule): Scanner {
    const isSegment = charTest(rule.segmentClass);
    const isWord = charTest(rule.wordClass);
    const wordAt = (text: string, at: number): boolean =>
        at >= 0 && at < text.length && isWord(text[at] as string);
    const isBoundary = (text: string, at: number): boolean => wordAt(text, at - 1) !== wordAt(text, at);

    const matchAt = (text: string, start: number): Match => {
        let position = start + rule.lead.length;
        let firstRunEnd = position;
        for (let segment = 0; segment < rule.segments; segment++) {
            const end = runEnd(text, position, isSegment);
            if (segment === 0) firstRunEnd = end;
            const length = end - position;
            if (length < rule.minSegment) return { failedRunEnd: firstRunEnd };
            if (segment < rule.segments - 1) {
                if (text[end] !== rule.separator) return { failedRunEnd: firstRunEnd };
                position = end + 1;
                continue;
            }
            for (let take = length; take >= rule.minSegment; take--) {
                if (isBoundary(text, position + take)) return { end: position + take };
            }
        }
        return { failedRunEnd: firstRunEnd };
    };

    return (text) => {
        const ranges: Range[] = [];
        let from = 0;
        let skipUntil = 0;
        for (let start = text.indexOf(rule.lead, from); start !== -1; start = text.indexOf(rule.lead, from)) {
            from = start + 1;
            const isSkipped = start < skipUntil || !isBoundary(text, start);
            if (isSkipped) continue;
            const match = matchAt(text, start);
            if ('failedRunEnd' in match) {
                skipUntil = match.failedRunEnd;
                continue;
            }
            ranges.push([start, match.end]);
            from = match.end;
        }
        return ranges;
    };
}
