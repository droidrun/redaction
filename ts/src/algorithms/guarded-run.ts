/**
 * guarded-run — the run of value characters of a pair: characters of the plain
 * class, and a backslash that is not followed by a character of the stop class
 * (`\"` ends the value, `\x` does not). One definition for the keyword, the
 * unquoted-pair and the cookie rules. Linear, no backtracking.
 */
import { charTest, type CharTest } from '../portable.js';

export type RunClasses = { plain: CharTest; stop: CharTest };

export function runClasses(rule: { plainChar?: unknown; escapeStop?: unknown }): RunClasses {
    return { plain: charTest(String(rule.plainChar)), stop: charTest(String(rule.escapeStop)) };
}

/** End of the run that starts at `from`, at most `max` code units long. */
export function guardedRunEnd(
    text: string,
    from: number,
    classes: RunClasses,
    max = Number.POSITIVE_INFINITY,
): number {
    let end = from;
    while (end < text.length && end - from < max) {
        const unit = text[end] as string;
        const next = text[end + 1];
        const isGuardedBackslash = unit === '\\' && !(next !== undefined && classes.stop(next));
        if (!classes.plain(unit) && !isGuardedBackslash) break;
        end += 1;
    }
    return end;
}
