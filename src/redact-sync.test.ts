/**
 * redact-sync.test.ts — the sync entry: limits (fail closed), cycles, skip
 * keys, never-throw, and agreement with the async path.
 */
import { describe, expect, test } from 'bun:test';
import { redactJsonValue, redactJsonValueSync, redactText, redactTextSync } from './index.js';

const FAKE = 'Zk9-fakeMARKER_7q2x';

describe('redactTextSync', () => {
    test('returns text and hits (rule id and range, never the match)', () => {
        const { text, hits } = redactTextSync(`login password: ${FAKE}`);
        expect(text).toBe('login password: [REDACTED:generic-keyword]');
        expect(hits).toEqual([{ ruleId: 'generic-keyword', range: [16, 16 + FAKE.length] }]);
    });

    test('text below the scan floor is returned as is', () => {
        expect(redactTextSync('pw=abc')).toEqual({ text: 'pw=abc', hits: [] });
    });

    test('text over maxChars is replaced whole: no prefix of a straddling secret is exposed', () => {
        const input = `${'a '.repeat(50)}password=${FAKE}`;
        const { text, hits } = redactTextSync(input, { maxChars: 100 });
        expect(text).toBe('[REDACTED:size-limit]');
        expect(hits).toEqual([{ ruleId: 'size-limit', range: [0, input.length] }]);
    });

    test('the limit applies before the short-text shortcut', () => {
        expect(redactTextSync('abcdefg', { maxChars: 3 }).text).toBe('[REDACTED:size-limit]');
        expect(redactTextSync('abc', { maxChars: 3 }).text).toBe('abc');
    });

    test('non-string input never throws', () => {
        for (const value of [null, undefined, 5, true, {}, Symbol('s')]) {
            expect(() => redactTextSync(value as unknown as string)).not.toThrow();
        }
        expect(redactTextSync(5 as unknown as string).text).toBe('5');
    });

    test('adversarial input stays linear: many unterminated quotes', () => {
        const input = 'password="'.repeat(20_000);
        const started = performance.now();
        const { text } = redactTextSync(input);
        expect(performance.now() - started).toBeLessThan(2_000);
        expect(text).not.toContain('password="p');
    });

    test('adversarial input stays linear: one long hyphenated run', () => {
        const input = 'a-'.repeat(200_000);
        const started = performance.now();
        redactTextSync(input);
        expect(performance.now() - started).toBeLessThan(2_000);
    });
});

describe('redactJsonValueSync', () => {
    test('does not mutate its input', () => {
        const input = { password: 'x', nested: { note: `password=${FAKE}` } };
        const copy = structuredClone(input);
        redactJsonValueSync(input);
        expect(input).toEqual(copy);
    });

    test('default skip keys are type and id; opts.skipKeys replaces them', () => {
        const value = `password=${FAKE}`;
        expect(redactJsonValueSync({ type: value, id: value, other: value })).toEqual({
            type: value,
            id: value,
            other: 'password=[REDACTED:generic-keyword]',
        });
        expect(redactJsonValueSync({ type: value, keep: value }, { skipKeys: new Set(['keep']) })).toEqual({
            type: 'password=[REDACTED:generic-keyword]',
            keep: value,
        });
    });

    test('a skipped key keeps even a secret-named value', () => {
        const out = redactJsonValueSync({ token: 'abc' }, { skipKeys: new Set(['token']) });
        expect(out).toEqual({ token: 'abc' });
    });

    test('nesting beyond maxDepth is replaced, not walked', () => {
        let deep: unknown = { password: FAKE };
        for (let i = 0; i < 10; i++) deep = { a: deep };
        const out = redactJsonValueSync(deep, { maxDepth: 5 });
        expect(JSON.stringify(out)).toBe('{"a":{"a":{"a":{"a":{"a":"[REDACTED:depth-limit]"}}}}}');
        expect(JSON.stringify(out)).not.toContain(FAKE);
    });

    test('the default depth bound survives a 100k-deep value without a stack overflow', () => {
        let deep: unknown = 'x';
        for (let i = 0; i < 100_000; i++) deep = { a: deep };
        expect(() => redactJsonValueSync(deep)).not.toThrow();
    });

    test('every visited value counts: traversal stops at maxNodes with a marker', () => {
        const wide = Array.from({ length: 1000 }, (_, i) => i);
        const out = redactJsonValueSync(wide, { maxNodes: 10 }) as unknown[];
        expect(out).toHaveLength(10);
        expect(out[9]).toBe('[REDACTED:size-limit]');
    });

    test('a wide object stops at the budget without reading every key', () => {
        const wide: Record<string, unknown> = {};
        for (let i = 0; i < 50_000; i++) wide[`k${i}`] = i;
        const out = redactJsonValueSync(wide, { maxNodes: 100 }) as Record<string, unknown>;
        expect(Object.keys(out)).toHaveLength(100);
        expect(Object.values(out).at(-1)).toBe('[REDACTED:size-limit]');
    });

    test('a leaf over the maxChars budget is replaced whole (no prefix exposure)', () => {
        const out = redactJsonValueSync({ a: 'x'.repeat(60), b: 'short' }, { maxChars: 50 }) as {
            a: string;
            b: string;
        };
        expect(out.a).toBe('[REDACTED:size-limit]');
        expect(out.b).toBe('[REDACTED:size-limit]');
    });

    test('typed arrays and buffers are replaced, never walked', () => {
        const out = redactJsonValueSync({ a: Buffer.from('x'.repeat(1000)), b: new Uint8Array(10) });
        expect(out).toEqual({ a: '[REDACTED:size-limit]', b: '[REDACTED:size-limit]' });
    });

    test('an Error is read as name, message and stack, then scanned', () => {
        const out = redactJsonValueSync(new Error(`boom password=${FAKE}`)) as Record<string, string>;
        expect(out.name).toBe('Error');
        expect(out.message).toBe('boom password=[REDACTED:generic-keyword]');
        expect(out.stack).not.toContain(FAKE);
    });

    test('an object with toJSON is read through toJSON, then scanned', () => {
        const value = { toJSON: () => ({ note: `password=${FAKE}` }) };
        const out = redactJsonValueSync({ v: value });
        expect(out).toEqual({ v: { note: 'password=[REDACTED:generic-keyword]' } });
    });

    test('skip keys keep primitives but containers below them are walked', () => {
        const out = redactJsonValueSync({ type: { password: FAKE }, id: `password=${FAKE}` });
        expect(out).toEqual({ type: { password: '[REDACTED:key-context]' }, id: `password=${FAKE}` });
    });

    test('a secret in an object key is replaced in the key', () => {
        const out = redactJsonValueSync({ [`Bearer ${FAKE}`]: 1 });
        expect(out).toEqual({ 'Bearer [REDACTED:auth-header]': 1 });
    });

    test('token counts stay numbers, secret numbers are replaced', () => {
        const out = redactJsonValueSync({ max_tokens: 100, tokens: [1, 2], pin: 1234, token: 5 });
        const ph = '[REDACTED:key-context]';
        expect(out).toEqual({ max_tokens: 100, tokens: [1, 2], pin: ph, token: ph });
    });

    test('a circular reference becomes a placeholder', () => {
        const value: Record<string, unknown> = { name: 'n' };
        value.self = value;
        expect(redactJsonValueSync(value)).toEqual({ name: 'n', self: '[REDACTED:circular]' });
    });

    test('the same object twice (not a cycle) is walked both times', () => {
        const shared = { password: 'x' };
        expect(redactJsonValueSync({ a: shared, b: shared })).toEqual({
            a: { password: '[REDACTED:key-context]' },
            b: { password: '[REDACTED:key-context]' },
        });
    });

    test('a key named __proto__ stays an own key', () => {
        const out = redactJsonValueSync(JSON.parse('{"__proto__":{"password":"x"}}')) as object;
        expect(Object.keys(out)).toEqual(['__proto__']);
        expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    });

    test('primitives, null and dates pass through', () => {
        const date = new Date(0);
        const value = [1, true, null, undefined, date];
        expect(redactJsonValueSync(value)).toEqual(value);
    });

    test('collects hits when asked', () => {
        const stats = { hits: [] as { ruleId: string; range: readonly [number, number] }[] };
        redactJsonValueSync({ password: 'abc', note: `password=${FAKE}` }, { stats });
        expect(stats.hits.map((hit) => hit.ruleId)).toEqual(['key-context', 'generic-keyword']);
    });

    test('a getter that throws fails closed', () => {
        const value = { get boom(): string { throw new Error('nope'); } };
        expect(redactJsonValueSync(value)).toBe('[REDACTED:redaction-failed]');
    });
});

describe('sync and async agree on what the sync rules find', () => {
    const inputs = [
        `password: ${FAKE}`,
        'Authorization: Bearer abc.def-1=',
        'https://example.test/cb?token=abc123&x=1',
        'ghp_16C7e42F292c6912E7710c838347Ae178B4a',
        '{"api_key": "has space, and comma"}',
    ];
    test.each(inputs)('%s', async (input) => {
        expect((await redactText(input)).text).toBe(redactTextSync(input).text);
    });

    test('JSON with secret-named keys', async () => {
        const value = { headers: { 'X-Api-Key': 'k', note: 'Bearer abc.def-1=' }, list: [{ pin: 1234 }] };
        expect(await redactJsonValue(value, { hits: [] })).toEqual(redactJsonValueSync(value));
    });
});
