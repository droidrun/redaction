/**
 * redact-value.test.ts — the generic recursive JSON-value walker: structural
 * skip-list (never touched, regardless of value shape) and the key-context
 * rule (force-redact a string value reached through a credential-suspicious
 * key, even when the value alone wouldn't trip any secretlint rule).
 */
import { describe, expect, test } from 'bun:test';
import { redactJsonValue, STRUCTURAL_SKIP_KEYS, type RedactValueStats } from './redact-value.js';

function newStats(): RedactValueStats {
    return { hits: [] };
}

describe('key-context rule', () => {
    test('a short, low-entropy value under a "password" key is force-redacted even ' +
        'though it alone would never trip a rule', async () => {
        const stats = newStats();
        const out = (await redactJsonValue({ password: 'abc123' }, stats, undefined)) as Record<
            string,
            unknown
        >;
        expect(out.password).not.toBe('abc123');
        expect(String(out.password)).toMatch(/^\[REDACTED:key-context/);
        expect(stats.hits.some((h) => h.ruleId === 'key-context')).toBe(true);
    });

    test('the KEY itself is never touched, only the value', async () => {
        const stats = newStats();
        const out = (await redactJsonValue({ AWS_SECRET_ACCESS_KEY: 'x' }, stats, undefined)) as Record<
            string,
            unknown
        >;
        expect(Object.keys(out)).toEqual(['AWS_SECRET_ACCESS_KEY']);
    });

    test('matches case-insensitively and on common aliases (secret, token, apiKey, ' +
        'accessKey, clientSecret, privateKey, credential)', async () => {
        const stats = newStats();
        const input = {
            secret: 'v1',
            token: 'v2',
            apiKey: 'v3',
            accessKey: 'v4',
            clientSecret: 'v5',
            privateKey: 'v6',
            credential: 'v7',
        };
        const out = (await redactJsonValue(input, stats, undefined)) as Record<string, unknown>;
        for (const key of Object.keys(input)) {
            expect(String(out[key])).toMatch(/^\[REDACTED:key-context\]$/);
        }
    });

    test('a NON-suspicious key with the same value shape goes through the normal ' +
        'detector instead (not force-redacted)', async () => {
        const stats = newStats();
        // "notes" isn't credential-suspicious and "just a note" won't trip any rule.
        const out = (await redactJsonValue({ notes: 'just a note' }, stats, undefined)) as Record<
            string,
            unknown
        >;
        expect(out.notes).toBe('just a note');
    });

    test('empty string value under a suspicious key is left as-is (nothing to redact)', async () => {
        const stats = newStats();
        const out = (await redactJsonValue({ password: '' }, stats, undefined)) as Record<string, unknown>;
        expect(out.password).toBe('');
    });
});

describe('structural skip-list', () => {
    test('every listed key is untouched even when its value is adversarially credential-shaped', async () => {
        const stats = newStats();
        // Would trip the generic-keyword rule if scanned.
        const adversarial = 'password: S0mmer2026!xTr0ub4dor';
        const input: Record<string, unknown> = {};
        for (const key of STRUCTURAL_SKIP_KEYS) input[key] = adversarial;
        const out = (await redactJsonValue(input, stats, undefined)) as Record<string, unknown>;
        for (const key of STRUCTURAL_SKIP_KEYS) {
            expect(out[key]).toBe(adversarial);
        }
        expect(stats.hits).toEqual([]);
    });

    test('a structural key does not gate its SIBLING content keys — only its own ' +
        'value is skipped', async () => {
        const stats = newStats();
        const out = (await redactJsonValue(
            { toolCallId: 'call_abc123', errorText: 'password: S0mmer2026!xTr0ub4dor' },
            stats,
        )) as Record<string, unknown>;
        expect(out.toolCallId).toBe('call_abc123');
        expect(out.errorText).not.toContain('S0mmer2026!xTr0ub4dor');
    });
});

describe('recursion', () => {
    test('nested objects: key-context applies at every depth', async () => {
        const stats = newStats();
        const out = (await redactJsonValue({ params: { username: 'alice', password: 'abc123' } }, stats)) as {
            params: Record<string, unknown>;
        };
        expect(out.params.username).toBe('alice');
        expect(String(out.params.password)).toMatch(/^\[REDACTED:key-context/);
    });

    test('arrays: elements have no key, so key-context never applies directly to ' +
        'them, but nested objects inside still recurse', async () => {
        const stats = newStats();
        const out = (await redactJsonValue({ items: [{ password: 'abc123' }, 'plain string'] }, stats)) as {
            items: unknown[];
        };
        expect(String((out.items[0] as Record<string, unknown>).password)).toMatch(/^\[REDACTED:key-context/);
        expect(out.items[1]).toBe('plain string');
    });

    test('non-string primitives pass through untouched', async () => {
        const stats = newStats();
        const out = await redactJsonValue({ count: 42, active: true, missing: null }, stats, undefined);
        expect(out).toEqual({ count: 42, active: true, missing: null });
    });
});

test('custom skip keys preserve their values while siblings are redacted', async () => {
    const stats = newStats();
    const secret = 'password: S0mmer2026!xTr0ub4dor';
    const out = await redactJsonValue(
        { customKey: secret, notes: secret },
        stats,
        undefined,
        { skipKeys: new Set(['customKey']) },
    );
    expect(out).toEqual({
        customKey: secret,
        notes: 'password: [REDACTED:generic-keyword:4dor]',
    });
    expect(stats.hits).toHaveLength(1);
});
