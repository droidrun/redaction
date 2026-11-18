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
            const footerAt = text.indexOf(rule.footerMarker, bodyStart);
            footer.lastIndex = footerAt;
            const found = footerAt !== -1 && footerAt < bodyEnd ? footer.exec(text) : null;
            covered = found ? footerAt + found[0].length : bodyEnd;
            ranges.push([start, covered]);
        }
        return ranges;
    };
}
