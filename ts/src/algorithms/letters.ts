/**
 * letters — the letter guard of the full tier (SPEC 5.6): "the code point before a position is not a
 * letter", with the letters fixed to the Unicode 15.0.0 categories Lu, Ll, Lt, Lm, Lo by the table of
 * `algorithms.json` (never the runtime's own `\p{L}`, which follows the runtime's Unicode version).
 */
import { ALGORITHMS_SPEC } from '../spec.js';

const HEX = 16;
const HIGH_SURROGATE_FIRST = 0xd800;
const HIGH_SURROGATE_LAST = 0xdbff;
const LOW_SURROGATE_FIRST = 0xdc00;
const LOW_SURROGATE_LAST = 0xdfff;
const ASTRAL_BASE = 0x10000;
const SURROGATE_BITS = 10;

function parseRanges(encoded: string): { lows: Uint32Array; highs: Uint32Array } {
    const items = encoded.split(',');
    const lows = new Uint32Array(items.length);
    const highs = new Uint32Array(items.length);
    items.forEach((item, index) => {
        const [low, high] = item.split('-');
        lows[index] = Number.parseInt(low as string, HEX);
        highs[index] = Number.parseInt(high ?? (low as string), HEX);
    });
    return { lows, highs };
}

const { lows: LOWS, highs: HIGHS } = parseRanges(ALGORITHMS_SPEC.letters.ranges);

/** True when `codePoint` is in the table (binary search over the sorted ranges). */
export function isLetter(codePoint: number): boolean {
    let low = 0;
    let high = LOWS.length - 1;
    while (low <= high) {
        const middle = (low + high) >> 1;
        if (codePoint < (LOWS[middle] as number)) high = middle - 1;
        else if (codePoint > (HIGHS[middle] as number)) low = middle + 1;
        else return true;
    }
    return false;
}

/** The code point that ends at `at` (exclusive): a surrogate pair is one code point, a lone surrogate is itself. */
function codePointBefore(text: string, at: number): number {
    const unit = text.charCodeAt(at - 1);
    const isLowSurrogate = unit >= LOW_SURROGATE_FIRST && unit <= LOW_SURROGATE_LAST;
    if (!isLowSurrogate || at < 2) return unit;
    const lead = text.charCodeAt(at - 2);
    if (lead < HIGH_SURROGATE_FIRST || lead > HIGH_SURROGATE_LAST) return unit;
    return ASTRAL_BASE + ((lead - HIGH_SURROGATE_FIRST) << SURROGATE_BITS) + (unit - LOW_SURROGATE_FIRST);
}

/** The letter guard: false (the start is refused) when the code point before `start` is a letter. */
export function passesLetterGuard(text: string, start: number): boolean {
    return start === 0 || !isLetter(codePointBefore(text, start));
}
