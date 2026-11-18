/** placeholder-value — "the candidate value is (the start of) one of our own placeholders". */
import { placeholderEndAt } from '../placeholder.js';

/** True when a placeholder starts at `start` and reaches at least `end`. */
export function isPlaceholderValue(text: string, start: number, end: number): boolean {
    const placeholderEnd = placeholderEndAt(text, start);
    return placeholderEnd !== -1 && placeholderEnd >= end;
}
