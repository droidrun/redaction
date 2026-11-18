/**
 * recheck-gate.test.ts — the decision on a recheck verdict: a verdict that is not "safe" is never erased, it is
 * confirmed by the scaling run (fail, with the attack) or reported as a warning with the attack (never silent);
 * a verdict without an attack string fails; the attack string is built at the size asked for.
 */
import { expect, test } from 'bun:test';
import { attackAtSize, recheckGate } from './recheck-gate.ts';

const ATTACK = {
    pumps: [{ prefix: 'a', pump: 'bc', bias: 1 }],
    suffix: '!',
    base: 10,
    string: 'abcbc!',
};
const vulnerable = { status: 'vulnerable', attack: ATTACK, complexity: { summary: 'polynomial' } };

test('safe passes without a warning', async () => {
    const gate = await recheckGate('p', 'x', {
        check: async () => ({ status: 'safe' }),
        confirm: () => 'never',
    });
    expect(gate).toEqual({});
});

test('vulnerable and confirmed by the scaling run fails and carries the attack', async () => {
    const gate = await recheckGate('p', 'x', {
        check: async () => vulnerable,
        confirm: () => 'JavaScript: slow',
    });
    expect(gate.problem).toContain('confirms it (JavaScript: slow)');
    expect(gate.problem).toContain('attack');
    expect(gate.warning).toBeUndefined();
});

test('vulnerable but not confirmed is a warning with the attack, never a silent pass', async () => {
    const gate = await recheckGate('p', 'x', { check: async () => vulnerable, confirm: () => undefined });
    expect(gate.problem).toBeUndefined();
    expect(gate.warning).toContain('stays linear');
    expect(gate.warning).toContain('attack');
});

test('unknown, or vulnerable without an attack string, fails', async () => {
    const unknown = await recheckGate('p', 'x', {
        check: async () => ({ status: 'unknown' }),
        confirm: () => undefined,
    });
    expect(unknown.problem).toContain('unknown');
    const bare = await recheckGate('p', 'x', {
        check: async () => ({ status: 'vulnerable' }),
        confirm: () => undefined,
    });
    expect(bare.problem).toContain('no attack string');
});

test('the attack string is built at the size asked for, with its prefix, bias and suffix', () => {
    const text = attackAtSize(ATTACK, 1000);
    expect(text.startsWith('abc')).toBe(true);
    expect(text.endsWith('!')).toBe(true);
    expect(text.length).toBeGreaterThan(990);
    expect(text.length).toBeLessThanOrEqual(1010);
    expect(attackAtSize(ATTACK, 3)).toBe('abcbc!');
});
