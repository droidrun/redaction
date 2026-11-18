/**
 * pem-blocks — PEM private keys: header through footer; a block without footer is
 * redacted through the end of its body-looking run (fail closed). Also written with
 * literal `\n` in JSON text. A header inside an already covered block is skipped.
 */
import { charTest, compile, type Range } from '../portable.js';
import type { Scanner } from './regex-rule.js';
import type { Rule } from '../spec.js';

type PemRule = Rule & {
    header: string;
    footer: string;
    footerMarker: string;
    bodyChar: string;
    bodyLimit: number;
};

/** First index in `[from, before)` where `marker` starts, or -1. The marker may run past `before`; a start at
 *  or after `before` does not count, so the search never leaves the body run and stays linear overall. */
function markerBefore(text: string, marker: string, from: number, before: number): number {
    for (let i = from; i < before; i++) {
        if (text.startsWith(marker, i)) return i;
    }
    return -1;
}

export function preparePemBlocks(rule: PemRule): Scanner {
    const header = compile(rule.header, 'g');
    const footer = compile(rule.footer, 'y');
    const isBodyChar = charTest(rule.bodyChar);
    return (text) => {
        const ranges: Range[] = [];
        let covered = 0;
        for (const match of text.matchAll(header)) {
            const start = match.index ?? 0;
            if (start < covered) continue;
            const bodyStart = start + match[0].length;
            const limit = Math.min(text.length, bodyStart + rule.bodyLimit);
            let bodyEnd = bodyStart;
            while (bodyEnd < limit && isBodyChar(text[bodyEnd] ?? '')) bodyEnd += 1;
            const footerAt = markerBefore(text, rule.footerMarker, bodyStart, bodyEnd);
            footer.lastIndex = footerAt;
            const found = footerAt !== -1 ? footer.exec(text) : null;
            covered = found ? footerAt + found[0].length : bodyEnd;
            ranges.push([start, covered]);
        }
        return ranges;
    };
}
