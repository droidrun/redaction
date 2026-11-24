/**
 * word-before — the word that stands just before a position, for rules that keep a match in a context
 * (`version 1.2.3.4`, `error code 123456`; SPEC 4.1 `ignoreAfterWords`).
 */
import type { CharTest } from '../portable.js';

const isLetter = (unit: string | undefined): boolean => {
    return unit !== undefined && ((unit >= 'a' && unit <= 'z') || (unit >= 'A' && unit <= 'Z'));
};

/** The lower-case ASCII letters that end just before `at`, after skipping the units of `isGap` there.
 *  Empty when no letter stands there. */
export function wordBefore(text: string, at: number, isGap: CharTest): string {
    let end = at;
    while (end > 0 && isGap(text[end - 1] as string)) end -= 1;
    let start = end;
    while (start > 0 && isLetter(text[start - 1])) start -= 1;
    return text.slice(start, end).toLowerCase();
}
