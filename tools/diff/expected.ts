/**
 * What the differential test must cover. A runner that reports less than its row here fails the job, so a
 * tier cannot silently drop out of the comparison (a renamed argument, a failed detection).
 *
 * To add coverage, update this table in the same pull request. A runner that reports more than the table
 * is noted, not failed.
 */
import type { Mode, Tier } from './protocol.ts';

export const EXPECTED: Record<Tier, Record<Mode, readonly string[]>> = {
    standard: { compat: ['ts', 'python', 'go'], strict: ['ts', 'python', 'go'] },
    full: { compat: ['ts', 'python', 'go'], strict: ['ts', 'python', 'go'] },
};

/** Every (tier, mode) row must have at least this many cases compared (or run, for a row of one runner). */
export const MIN_CASES = 5000;
