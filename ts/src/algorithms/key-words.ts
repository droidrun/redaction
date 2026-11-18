/**
 * key-words — splits a key into lower-case words at separators and camelCase humps:
 * `clientSecret` -> client, secret; `APIKey` -> api, key; `x-auth-token` -> x, auth, token.
 *
 * At each position the first of these applies (everything else is a separator):
 *   1. a run of capitals, if no lower-case letter follows it; if one does, the run
 *      without its last capital (that capital starts the next word) — `APIKey` -> API, Key;
 *   2. an optional capital and a run of lower-case letters;
 *   3. a run of digits.
 * Only ASCII letters and digits form words.
 */
import { runEnd } from '../portable.js';

const isUpper = (unit: string | undefined): boolean => unit !== undefined && unit >= 'A' && unit <= 'Z';
const isLower = (unit: string | undefined): boolean => unit !== undefined && unit >= 'a' && unit <= 'z';
const isDigit = (unit: string | undefined): boolean => unit !== undefined && unit >= '0' && unit <= '9';

/** End of the word that starts at `start`, or `start` when none does. */
function wordEnd(key: string, start: number): number {
    if (isUpper(key[start])) {
        const capitals = runEnd(key, start, isUpper);
        if (!isLower(key[capitals])) return capitals;
        if (capitals - start >= 2) return capitals - 1;
    }
    const lowerStart = isUpper(key[start]) ? start + 1 : start;
    const lowerEnd = runEnd(key, lowerStart, isLower);
    if (lowerEnd > lowerStart) return lowerEnd;
    return isDigit(key[start]) ? runEnd(key, start, isDigit) : start;
}

export function splitKeyWords(key: string): string[] {
    const words: string[] = [];
    let at = 0;
    while (at < key.length) {
        const end = wordEnd(key, at);
        if (end === at) {
            at += 1;
            continue;
        }
        words.push(key.slice(at, end).toLowerCase());
        at = end;
    }
    return words;
}
