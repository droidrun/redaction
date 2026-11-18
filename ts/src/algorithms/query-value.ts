/**
 * query-value — the pieces that decide where a value ends inside a URL query:
 * the label before a keyword, the `&` cut, and percent-decoding with a defined
 * failure behaviour (a malformed sequence leaves the whole value as it is).
 */
import type { Range } from '../portable.js';

/** Start of the identifier that holds the keyword at `keywordStart` (at most `lookback` back). */
export function labelStart(
    content: string,
    keywordStart: number,
    isIdentChar: (unit: string) => boolean,
    lookback: number,
): number {
    let start = keywordStart;
    while (start > 0 && keywordStart - start < lookback && isIdentChar(content[start - 1] ?? '')) {
        start -= 1;
    }
    return start;
}

/** Inside a URL query string (`?token=…&x=1`) a value ends at the next `&`.
 *  `label` is where the `label=value` identifier began. */
export function trimQueryValue(content: string, label: number, range: readonly [number, number]): Range {
    const before = content[label - 1];
    if (before !== '?' && before !== '&') return [range[0], range[1]];
    // Only inside the value range: a search to the end of the text is quadratic on `?token=` repeated.
    for (let i = range[0]; i < range[1]; i++) {
        if (content[i] === '&') return [range[0], i];
    }
    return [range[0], range[1]];
}

/** `decodeURIComponent`, or the value itself when it holds a malformed escape. */
export function percentDecode(value: string): string {
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}
