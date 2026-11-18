/**
 * pem-key — PEM private keys of the upstream preset (SPEC 4.14): a header, a body of 100 to 10000 units of
 * the body class, a footer, and a body that is real base64 of a key (not a placeholder such as `...` or
 * `xxx`). Unlike `pem-blocks` (standard tier) an unterminated or invalid block is NOT a hit.
 *
 * The body class holds no `-`, so the body ends at the first unit outside it and the footer must start
 * exactly there; the optional line feeds around the body only move the body bounds by one unit.
 */
import { charTest, compile, runEnd, type CharTest, type Range } from '../portable.js';
import type { Rule } from '../spec.js';
import type { Scanner } from './regex-rule.js';
import { cachedRunEnd } from './scan-support.js';

type PemKeyRule = Rule & {
    header: string;
    footer: string;
    bodyClass: string;
    minBody: number;
    maxBody: number;
    newline: string;
    stripClass: string;
    stripLiteral: string;
    contentClass: string;
    padChar: string;
    minContent: number;
    magic: string[];
};

/** True when a body of `length` units can be chosen: with or without the line feed after the header
 *  (`leading`) and before the footer (`trailing`), at least `min` and at most `max` units. */
function hasBodyLength(rule: PemKeyRule, length: number, leading: boolean, trailing: boolean): boolean {
    const both = leading && trailing && length >= 2;
    const options = [
        length,
        ...(leading ? [length - 1] : []),
        ...(trailing ? [length - 1] : []),
        ...(both ? [length - 2] : []),
    ];
    return options.some((option) => option >= rule.minBody && option <= rule.maxBody);
}

/** The body without whitespace and without the two-unit text `\n`. */
function stripped(rule: PemKeyRule, body: string, isStrip: CharTest): string {
    let kept = '';
    for (let at = 0; at < body.length; at++) {
        if (isStrip(body[at] as string)) continue;
        if (body.startsWith(rule.stripLiteral, at)) {
            at += rule.stripLiteral.length - 1;
            continue;
        }
        kept += body[at];
    }
    return kept;
}

/** `[contentClass]+` then `padChar*`, at least `minContent` units, starting with one of `magic`. */
function isKeyContent(rule: PemKeyRule, content: string, isContent: CharTest, isPad: CharTest): boolean {
    const contentEnd = runEnd(content, 0, isContent);
    if (contentEnd === 0) return false;
    if (runEnd(content, contentEnd, isPad) !== content.length) return false;
    const hasMagic = rule.magic.some((prefix) => content.startsWith(prefix));
    return content.length >= rule.minContent && hasMagic;
}

export function preparePemKey(rule: PemKeyRule): Scanner {
    const header = compile(rule.header, 'g');
    const footer = compile(rule.footer, 'y');
    const isBody = charTest(rule.bodyClass);
    const isStrip = charTest(rule.stripClass);
    const isContent = charTest(rule.contentClass);
    const isPad = charTest(rule.padChar);
    return (text) => {
        const bodyRunEnd = cachedRunEnd(text, isBody);
        const ranges: Range[] = [];
        header.lastIndex = 0;
        for (let found = header.exec(text); found !== null; found = header.exec(text)) {
            const start = found.index;
            const bodyStart = start + found[0].length;
            header.lastIndex = start + 1;
            const bodyEnd = bodyRunEnd(bodyStart);
            const length = bodyEnd - bodyStart;
            const leading = text.startsWith(rule.newline, bodyStart);
            const trailing = length > 0 && text.startsWith(rule.newline, bodyEnd - 1);
            if (!hasBodyLength(rule, length, leading, trailing)) continue;
            footer.lastIndex = bodyEnd;
            const closing = footer.exec(text);
            if (closing === null) continue;
            const body = text.slice(bodyStart, bodyEnd);
            if (!isKeyContent(rule, stripped(rule, body, isStrip), isContent, isPad)) continue;
            const end = bodyEnd + closing[0].length;
            ranges.push([start, end]);
            header.lastIndex = end;
        }
        return ranges;
    };
}
