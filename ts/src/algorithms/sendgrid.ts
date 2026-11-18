/**
 * sendgrid-key — SendGrid API keys (SPEC 4.13): `SG.` + `\w{1,128}` + `.` + `\w{1,128}([-_]?)\w{1,128}`,
 * not followed by a word unit, and only a match of exactly `length` (69) units is a key. The expression
 * backtracks, so which match it finds decides what the scan consumes; the steps below are what it finds.
 */
import { charTest, type Range } from '../portable.js';
import type { Rule } from '../spec.js';
import { passesLetterGuard } from './letters.js';
import type { Scanner } from './regex-rule.js';
import { cachedRunEnd, nextStartOf } from './scan-support.js';

type SendgridRule = Rule & {
    lead: string;
    separator: string;
    wordClass: string;
    dash: string;
    maxSegment: number;
    length: number;
};

export function prepareSendgrid(rule: SendgridRule): Scanner {
    const isWord = charTest(rule.wordClass);
    return (text) => {
        const runEnd = cachedRunEnd(text, isWord);
        const twice = rule.maxSegment * 2;
        /** End of the match the expression finds after the second separator at `position`, or -1. */
        const tailEnd = (position: number): number => {
            const end = runEnd(position);
            const length = end - position;
            if (length === 0) return -1;
            if (length <= rule.maxSegment && text[end] === rule.dash) {
                const after = runEnd(end + 1);
                const joined = after - (end + 1);
                if (joined >= 1 && joined <= rule.maxSegment) return after;
            }
            return length >= 2 && length <= twice ? end : -1;
        };
        const matchEnd = (start: number): number => {
            const afterLead = start + rule.lead.length;
            const firstEnd = runEnd(afterLead);
            const firstLength = firstEnd - afterLead;
            const isFirstValid = firstLength >= 1 && firstLength <= rule.maxSegment;
            if (!isFirstValid || text[firstEnd] !== rule.separator) return -1;
            return tailEnd(firstEnd + 1);
        };
        const nextStart = nextStartOf(text, [rule.lead]);
        const ranges: Range[] = [];
        let from = 0;
        for (let start = nextStart(from); start !== -1; start = nextStart(from)) {
            from = start + 1;
            if (!passesLetterGuard(text, start)) continue;
            const end = matchEnd(start);
            if (end === -1) continue;
            from = end;
            if (end - start === rule.length) ranges.push([start, end]);
        }
        return ranges;
    };
}
