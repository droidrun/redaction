/**
 * scan-support — small linear helpers the full-tier scanners share. Both keep state for ONE scan of ONE
 * text, so a scanner makes them at the start of each call: the next occurrence of any of a few literals
 * (each literal searched forward only) and the end of a run of units of a class, remembered for the run
 * last measured (every start inside one run gets the same end for free).
 */
import type { CharTest } from '../portable.js';

export type NextStart = (from: number) => number;
export type RunEnd = (from: number) => number;

const UNKNOWN = -2;
const NONE = -1;

/** The first position at or after `from` where one of `literals` starts, or -1. `from` never goes back. */
export function nextStartOf(text: string, literals: readonly string[]): NextStart {
    const remembered = literals.map(() => UNKNOWN);
    return (from) => {
        let best = NONE;
        literals.forEach((literal, index) => {
            const known = remembered[index] as number;
            const isStale = known !== NONE && known < from;
            const found = known === UNKNOWN || isStale ? text.indexOf(literal, from) : known;
            remembered[index] = found;
            if (found !== NONE && (best === NONE || found < best)) best = found;
        });
        return best;
    };
}

/** End of the maximal run of units of the class that starts at `from` (`from` itself when there is none). */
export function cachedRunEnd(text: string, inClass: CharTest): RunEnd {
    let low = 0;
    let high = 0;
    return (from) => {
        if (from >= low && from < high) return high;
        let end = from;
        while (end < text.length && inClass(text[end] as string)) end += 1;
        low = from;
        high = end;
        return end;
    };
}
