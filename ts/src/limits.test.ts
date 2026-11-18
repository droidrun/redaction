/**
 * limits.test.ts — the default limits of the sync and strict walkers and the `last4`
 * threshold sit exactly where SPEC.md puts them: one unit inside passes, one beyond is replaced.
 */
import { expect, test } from 'bun:test';
import { buildPlaceholder, redactJsonValueSync } from './index.js';

const LIMIT_MARK = '[REDACTED:size-limit]';
const DEPTH_MARK = '[REDACTED:depth-limit]';

function nested(levels: number): unknown {
    let value: unknown = 'leaf';
    for (let i = 0; i < levels; i++) value = [value];
    return value;
}

function depthOf(value: unknown): number {
    let depth = 0;
    let cursor = value;
    while (Array.isArray(cursor)) {
        cursor = cursor[0];
        depth += 1;
    }
    return depth;
}

test.each(['compat', 'strict'] as const)('%s: 499999 array elements fit, the 500000th does not', (mode) => {
    const fits = redactJsonValueSync(new Array(499_999).fill(1), { mode }) as unknown[];
    expect(fits).toHaveLength(499_999);
    expect(fits.includes(LIMIT_MARK)).toBe(false);
    const over = redactJsonValueSync(new Array(500_000).fill(1), { mode }) as unknown[];
    expect(over[499_998]).toBe(1);
    expect(over[499_999]).toBe(LIMIT_MARK);
});

test.each(['compat', 'strict'] as const)(
    '%s: 64 nested arrays are walked, the 65th is depth-limited',
    (mode) => {
        const fits = redactJsonValueSync(nested(64), { mode });
        expect(depthOf(fits)).toBe(64);
        expect(JSON.stringify(fits)).not.toContain(DEPTH_MARK);
        const over = redactJsonValueSync(nested(65), { mode });
        expect(depthOf(over)).toBe(64);
        expect(JSON.stringify(over)).toContain(DEPTH_MARK);
    },
);

test.each(['compat', 'strict'] as const)(
    '%s: 4000000 characters of leaves fit, one more does not',
    (mode) => {
        const half = 'ab '.repeat(666_666);
        const rest = 'a'.repeat(4_000_000 - half.length);
        expect(redactJsonValueSync([half, rest], { mode })).toEqual([half, rest]);
        expect(redactJsonValueSync([half, `${rest}a`], { mode })).toEqual([half, LIMIT_MARK]);
    },
);

test('last4 is added from 16 characters, not below', () => {
    expect(buildPlaceholder('aws', 'a'.repeat(15))).toBe('[REDACTED:aws]');
    expect(buildPlaceholder('aws', `${'a'.repeat(12)}wxyz`)).toBe('[REDACTED:aws:wxyz]');
});
