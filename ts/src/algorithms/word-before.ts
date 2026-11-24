/**
 * word-before — the word that stands just before a position, for rules that keep a match in a context
 * (`version 1.2.3.4`, `error code 123456`; SPEC 4.1 `ignoreAfterWords`).
 */
import type { CharTest } from '../portable.js';
import { labelStart } from './query-value.js';

const isLetter = (unit: string): boolean => (unit >= 'a' && unit <= 'z') || (unit >= 'A' && unit <= 'Z');

/** The lower-case ASCII letters that end just before `at`, after skipping the units of `isGap` there.
 *  Empty when no letter stands there. */
export function wordBefore(text: string, at: number, isGap: CharTest): string {
    const end = labelStart(text, at, isGap, Number.POSITIVE_INFINITY);
    const start = labelStart(text, end, isLetter, Number.POSITIVE_INFINITY);
    return text.slice(start, end).toLowerCase();
}
