/**
 * redact-value.test.ts — the generic recursive JSON-value walker: structural
 * skip-list (never touched, regardless of value shape) and the key-context
 * rule (force-redact a string value reached through a credential-suspicious
 * key, even when the value alone wouldn't trip any secretlint rule).
 */
import { describe, expect, test } from 'bun:test';
import { redactJsonValue, STRUCTURAL_SKIP_KEYS, type RedactValueStats } from './redact-value.js';
import { redactJsonValueSync } from './redact-sync.js';

// Explicit consumer keys from the original structural skip list.
const LEGACY_SKIP_KEYS: ReadonlySet<string> = new Set([
    'type',
    'id',
    'toolCallId',
    'state',
    'toolName',
    'questionId',
    'questionID',
    'fileId',
    'mimeType',
    'filename',
    'url',
    'status',
    'errorClass',
    'deviceId',
    'verb',
    'buildId',
    'phase',
    'slug',
    'agentName',
    'messageId',
    'eventType',
    // Charset-validated avatar identifier, never credential content.
    'avatarSeed',
    'code',
]);

function newStats(): RedactValueStats {
    return { hits: [] };
}

describe('key-context rule', () => {
    test('a short, low-entropy value under a "password" key is force-redacted even ' +
        'though it alone would never trip a rule', async () => {
        const stats = newStats();
        const out = (await redactJsonValue({ password: 'abc123' }, stats)) as Record<
            string,
            unknown
        >;
        expect(out.password).not.toBe('abc123');
        expect(String(out.password)).toMatch(/^\[REDACTED:key-context/);
        expect(stats.hits.some((h) => h.ruleId === 'key-context')).toBe(true);
    });

    test('the KEY itself is never touched, only the value', async () => {
        const stats = newStats();
        const out = (await redactJsonValue({ AWS_SECRET_ACCESS_KEY: 'x' }, stats)) as Record<
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
        const out = (await redactJsonValue(input, stats)) as Record<string, unknown>;
        for (const key of Object.keys(input)) {
            expect(String(out[key])).toMatch(/^\[REDACTED:key-context\]$/);
        }
    });

    test('a NON-suspicious key with the same value shape goes through the normal ' +
        'detector instead (not force-redacted)', async () => {
        const stats = newStats();
        // "notes" isn't credential-suspicious and "just a note" won't trip any rule.
        const out = (await redactJsonValue({ notes: 'just a note' }, stats)) as Record<
            string,
            unknown
        >;
        expect(out.notes).toBe('just a note');
    });

    test('empty string value under a suspicious key is left as-is (nothing to redact)', async () => {
        const stats = newStats();
        const out = (await redactJsonValue({ password: '' }, stats)) as Record<string, unknown>;
        expect(out.password).toBe('');
    });
});

describe('structural skip-list', () => {
    test('every listed key is untouched even when its value is adversarially credential-shaped', async () => {
        const stats = newStats();
        // Would trip the generic-keyword rule if scanned.
        const adversarial = 'password: S0mmer2026!xTr0ub4dor';
        const input: Record<string, unknown> = {};
        for (const key of LEGACY_SKIP_KEYS) input[key] = adversarial;
        const out = (await redactJsonValue(
            input, stats, { skipKeys: LEGACY_SKIP_KEYS },
        )) as Record<string, unknown>;
        for (const key of LEGACY_SKIP_KEYS) {
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
            { skipKeys: LEGACY_SKIP_KEYS },
        )) as Record<string, unknown>;
        expect(out.toolCallId).toBe('call_abc123');
        expect(out.errorText).not.toContain('S0mmer2026!xTr0ub4dor');
    });

    test('custom skip keys preserve their values while siblings are redacted', async () => {
        const stats = newStats();
        const secret = 'password: S0mmer2026!xTr0ub4dor';
        const out = await redactJsonValue(
            { customKey: secret, notes: secret, type: secret },
            stats,
            { skipKeys: new Set(['customKey']) },
        );
        expect(out).toEqual({
            customKey: secret,
            notes: 'password: [REDACTED:generic-keyword]',
            type: 'password: [REDACTED:generic-keyword]',
        });
        expect(stats.hits).toHaveLength(2);
    });

    test('the minimal default preserves type and id but scans url and code', async () => {
        const stats = newStats();
        const secret = 'password: S0mmer2026!xTr0ub4dor';
        const out = await redactJsonValue({ type: secret, id: secret, url: secret, code: secret }, stats);
        expect([...STRUCTURAL_SKIP_KEYS]).toEqual(['type', 'id']);
        expect(out).toEqual({
            type: secret,
            id: secret,
            url: 'password: [REDACTED:generic-keyword]',
            code: 'password: [REDACTED:generic-keyword]',
        });
        expect(stats.hits).toHaveLength(2);
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
        const out = await redactJsonValue({ count: 42, active: true, missing: null }, stats);
        expect(out).toEqual({ count: 42, active: true, missing: null });
    });
});

describe('object keys in the full tier (SPEC 9.4)', () => {
    const NPM = `npm_${'A'.repeat(36)}`;

    test('a key that is a full-tier token is replaced in compat and strict, with its hit', async () => {
        for (const mode of ['compat', 'strict'] as const) {
            const stats = { hits: [] as Array<{ ruleId: string }> };
            const out = await redactJsonValue({ [NPM]: 1, normal_key_name: 2 }, stats as never, { mode });
            expect(out).toEqual({ '[REDACTED:npm]': 1, normal_key_name: 2 });
            expect(stats.hits.map((hit) => hit.ruleId)).toEqual(['@secretlint/secretlint-rule-npm']);
        }
    });

    test('the sync entry still reads keys with the standard rules only', () => {
        expect(redactJsonValueSync({ [NPM]: 1 })).toEqual({ [NPM]: 1 });
    });
});

describe('key collisions in the walkers (SPEC 8)', () => {
    const GH = `ghp_${'a'.repeat(36)}`;

    test('the sync node limit does not overwrite an earlier entry', () => {
        const out = redactJsonValueSync({ [GH]: 'keep-me', '[REDACTED:github]': 2 }, { maxNodes: 2 });
        expect(out).toEqual({
            '[REDACTED:github#2]': 'keep-me',
            '[REDACTED:github]': '[REDACTED:size-limit]',
        });
    });

    test('keys are scanned with opts.detect like leaves, in compat and in strict', async () => {
        const detect = async (text: string) =>
            text === 'custom-key-name' ? [{ ruleId: 'custom', range: [0, text.length] as const }] : [];
        for (const mode of ['compat', 'strict'] as const) {
            const input = { 'custom-key-name': 1, other: 2 };
            const out = await redactJsonValue(input, { hits: [] }, { mode, detect });
            expect(out).toEqual({ '[REDACTED:custom]': 1, other: 2 });
        }
    });

    test('a failing opts.detect never leaves a secret key raw in compat', async () => {
        const detect = async (): Promise<never> => {
            throw new Error('detector down');
        };
        const out = await redactJsonValue({ [GH]: 1 }, { hits: [] }, { detect });
        expect(out).toEqual({ '[REDACTED:github]': 1 });
    });
});
