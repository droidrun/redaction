/**
 * dash-chain — Slack tokens (SPEC 4.12): a lead, `-`, then runs of alphanumerics joined by single dashes,
 * `\b(?:xoxb|xoxp|...)-(?:\d-)?(?:[a-zA-Z0-9]{1,40}-)+[a-zA-Z0-9]{1,40}\b` without backtracking. The chain
 * is every valid run (1 to `maxSegment` units, each but the last followed by `-`); the match ends at the last
 * run, or at the one before it when the last is followed by a word unit (`_`, no word boundary there).
 * The optional leading `\d-` changes nothing: it only moves the first run out of the repeated group.
 */
import { charTest, type Range } from '../portable.js';
import type { Rule } from '../spec.js';
import type { Scanner } from './regex-rule.js';
import { cachedRunEnd, nextStartOf } from './scan-support.js';

type DashChainRule = Rule & {
    leads: string[];
    separator: string;
    segmentClass: string;
    wordClass: string;
    maxSegment: number;
    minSegments: number;
};

export function prepareDashChain(rule: DashChainRule): Scanner {
    const isSegment = charTest(rule.segmentClass);
    const isWord = charTest(rule.wordClass);
    return (text) => {
        const runEnd = cachedRunEnd(text, isSegment);
        const wordAt = (at: number): boolean => at >= 0 && at < text.length && isWord(text[at] as string);
        /** End of the last run that may end the token, or -1. */
        const matchEnd = (afterLead: number): number => {
            const ends: number[] = [];
            let position = afterLead;
            for (;;) {
                const end = runEnd(position);
                const length = end - position;
                if (length < 1 || length > rule.maxSegment) break;
                ends.push(end);
                if (text[end] !== rule.separator) break;
                position = end + 1;
            }
            const endsOnBoundary = (end: number): boolean => !wordAt(end);
            const last = ends.length;
            const used = last > 0 && endsOnBoundary(ends[last - 1] as number) ? last : last - 1;
            return used >= rule.minSegments ? (ends[used - 1] as number) : -1;
        };
        const nextStart = nextStartOf(text, rule.leads);
        const ranges: Range[] = [];
        let from = 0;
        for (let start = nextStart(from); start !== -1; start = nextStart(from)) {
            from = start + 1;
            if (wordAt(start - 1)) continue;
            const lead = rule.leads.find((item) => text.startsWith(item, start)) as string;
            const afterLead = start + lead.length;
            if (text[afterLead] !== rule.separator) continue;
            const end = matchEnd(afterLead + 1);
            if (end === -1) continue;
            ranges.push([start, end]);
            from = end;
        }
        return ranges;
    };
}
