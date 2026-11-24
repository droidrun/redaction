/**
 * scaling-run.test.ts — the load guard re-measures a failing attack before it fails and takes the best time; the
 * three parallel runs report their problems in a fixed order, each under its own label.
 */
import { expect, test } from 'bun:test';
import { bestOfRetries, scalingProblems, SCALING_RETRIES, shardsOf, type Sizes } from './scaling-run.ts';
import { growthOfSizes } from './recheck-gate.ts';

const slow = (times: Sizes): boolean => growthOfSizes(times) !== undefined;
const SLOW: Sizes = { 100_000: 50, 1_000_000: 4000 };
const FAST: Sizes = { 100_000: 60, 1_000_000: 300 };

test('a failing measurement that passes on a re-measure is accepted with the best time per size', async () => {
    let calls = 0;
    const times = await bestOfRetries(SLOW, slow, async () => (++calls, FAST), () => undefined);
    expect(calls).toBe(1);
    expect(times).toEqual({ 100_000: 50, 1_000_000: 300 });
});

test('a measurement that keeps failing is re-measured exactly twice, then stays failing', async () => {
    let calls = 0;
    const reports: number[] = [];
    const times = await bestOfRetries(
        SLOW,
        slow,
        async () => (++calls, SLOW),
        (attempt) => reports.push(attempt),
    );
    expect(SCALING_RETRIES).toBe(2);
    expect(calls).toBe(2);
    expect(reports).toEqual([1, 2]);
    expect(slow(times)).toBe(true);
});

test('a measurement within the bounds is not re-measured', async () => {
    let calls = 0;
    await bestOfRetries(FAST, slow, async () => (++calls, FAST), () => undefined);
    expect(calls).toBe(0);
});

test('growth: 30 times and 3 s are the bounds', () => {
    expect(growthOfSizes({ 100_000: 100, 1_000_000: 3000 })).toBeUndefined();
    expect(growthOfSizes({ 100_000: 100, 1_000_000: 3001 })).toBe('100 ms at 100 KB, 3001 ms at 1 MB');
    expect(growthOfSizes({ 100_000: 1, 1_000_000: 301 })).toBe('10 ms at 100 KB, 301 ms at 1 MB');
});

test('runs that crash are reported per run, in the order JavaScript, Python, interpreter', async () => {
    const broken = [{ where: 'planted', source: '(' }];
    const problems = await scalingProblems(broken, [{ name: '"a"', unit: 'a' }], []);
    expect(problems).toEqual([
        'JavaScript scaling run did not finish (deadline or crash)',
        'Python scaling run did not finish (deadline or crash)',
    ]);
});

test('a safe pattern over a small attack list reports nothing', async () => {
    const safe = [{ where: 'safe', source: '[a-z]{1,8}x' }];
    const problems = await scalingProblems(safe, [{ name: '"a"', unit: 'a' }], undefined);
    expect(problems).toEqual([]);
});

test('shards are consecutive slices that together give the list back, in order', () => {
    const items = [1, 2, 3, 4, 5, 6, 7];
    expect(shardsOf(items, 3)).toEqual([[1, 2, 3], [4, 5, 6], [7]]);
    expect(shardsOf(items, 1)).toEqual([items]);
    expect(shardsOf([], 4)).toEqual([]);
});
