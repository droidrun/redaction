/**
 * exports.compat.test.ts — 0.1.1 exports keep working. chat-agents-api imports
 * exactly these names; their signatures and their results (but for the
 * documented placeholder default) must not change in a minor release.
 */
import { describe, expect, test } from 'bun:test';
import * as api from './index.js';
import {
    buildPlaceholder,
    CREDENTIAL_KEY_RE,
    detectSecrets,
    PLACEHOLDER_RE,
    redactJsonValue,
    redactText,
    shortenRuleId,
    STRUCTURAL_SKIP_KEYS,
    type Hit,
    type RedactTextOpts,
    type RedactValueOpts,
    type RedactValueStats,
} from './index.js';

describe('the 0.1.1 export list', () => {
    test.each([
        'detectSecrets', 'redactText', 'redactJsonValue', 'buildPlaceholder', 'shortenRuleId',
    ])('%s is a function', (name) => {
        expect(typeof (api as Record<string, unknown>)[name]).toBe('function');
    });

    test('constants keep their value', () => {
        expect([...STRUCTURAL_SKIP_KEYS]).toEqual(['type', 'id']);
        expect(CREDENTIAL_KEY_RE.flags).toBe('i');
        expect(CREDENTIAL_KEY_RE.source).toBe(
            'password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|' +
                'private[_-]?key|client[_-]?secret|credential',
        );
        expect(PLACEHOLDER_RE.test('[REDACTED:aws]')).toBe(true);
        expect(PLACEHOLDER_RE.test('[REDACTED:aws:ab12]')).toBe(true);
        expect(PLACEHOLDER_RE.test('prefix [REDACTED:aws]')).toBe(false);
    });

    test('buildPlaceholder(ruleId, matched) is unchanged (last4 from 16 characters)', () => {
        expect(buildPlaceholder('@secretlint/secretlint-rule-aws', 'a'.repeat(15))).toBe('[REDACTED:aws]');
        const matched = `${'a'.repeat(16)}wxyz`;
        expect(buildPlaceholder('mobilerun-redaction/jwt', matched)).toBe('[REDACTED:jwt:wxyz]');
        expect(shortenRuleId('mobilerun-redaction/generic-keyword')).toBe('generic-keyword');
    });

    test('the 0.1.1 call shapes type-check and run', async () => {
        const stats: RedactValueStats = { hits: [] };
        const opts: RedactTextOpts = { onEvent: () => {} };
        const valueOpts: RedactValueOpts = { skipKeys: new Set(['type']), onEvent: () => {} };
        const hits: Hit[] = await detectSecrets('password: S0mmer2026!xTr0ub4dor', opts);
        expect(hits).toHaveLength(1);
        const { text } = await redactText('password: S0mmer2026!xTr0ub4dor', opts);
        expect(text).toBe('password: [REDACTED:generic-keyword]');
        const out = await redactJsonValue({ type: 'x', password: 'abc123' }, stats, valueOpts);
        expect(out).toEqual({ type: 'x', password: '[REDACTED:key-context]' });
        expect(stats.hits).toHaveLength(1);
    });

    test('the custom detector override still replaces the scan', async () => {
        const out = await redactText('hello world', { detect: async () => [{ ruleId: 'x', range: [0, 5] }] });
        expect(out.text).toBe('[REDACTED:x] world');
    });

    test('opts.last4 gives the 0.1.1 placeholders back, in text and under a key', async () => {
        const secret = 'S0mmer2026!xTr0ub4dor';
        expect((await redactText(`password: ${secret}`, { last4: true })).text)
            .toBe('password: [REDACTED:generic-keyword:4dor]');
        const out = await redactJsonValue({ password: secret }, { hits: [] }, { last4: true });
        expect(out).toEqual({ password: '[REDACTED:key-context:4dor]' });
    });

    test('values redacted by 0.1.1 are recognised and left alone', async () => {
        const stored = 'password: [REDACTED:generic-keyword:4dor]';
        expect((await redactText(stored)).text).toBe(stored);
        expect(api.redactTextSync(stored).text).toBe(stored);
    });
});
