/**
 * token.test.ts — the `token` interpreter: a rule that names a check the package does not know stops at load
 * time, and the run memory is kept per variable-run part (SPEC 4.11).
 */
import { expect, test } from 'bun:test';
import { prepareToken } from './algorithms/token.js';
import { detectFullHits } from './full-rules.js';

test('an unknown check name throws when the rule is prepared', () => {
    const rule = { id: 'x', kind: 'token', parts: [{ lit: 'x_' }], check: 'no-such-check' };
    expect(() => prepareToken(rule as never)).toThrow('unknown check in the spec');
});

test('a long run behind a cluster of starts is measured once, not once per start', () => {
    // 166 starts of the GitHub app token, each within reach of one run of 990,000 units: a memory per class
    // measures that run at every start (about 1.6 s here), a memory per part measures it once (about 20 ms).
    const text = `${'ghs_0_'.repeat(166)}.${'a'.repeat(990_000)}`;
    const started = performance.now();
    detectFullHits(text);
    expect(performance.now() - started).toBeLessThan(400);
});

test('the cluster does not change what is found', () => {
    const token = `ghs_123_${'a'.repeat(5)}.${'b'.repeat(7)}.${'c'.repeat(9)}`;
    expect(
        detectFullHits(`${'ghs_0_'.repeat(3)}.${'a'.repeat(50)} ${token}`).map((hit) => hit.range),
    ).toEqual([
        [
            `${'ghs_0_'.repeat(3)}.${'a'.repeat(50)} `.length,
            `${'ghs_0_'.repeat(3)}.${'a'.repeat(50)} ${token}`.length,
        ],
    ]);
});
