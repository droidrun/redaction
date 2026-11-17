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

    test('text over maxChars is cut and the tail replaced, never passed through', () => {
        const tail = `password=${FAKE}`;
        const { text, hits } = redactTextSync(`${'a '.repeat(50)}${tail}`, { maxChars: 100 });
        expect(text).toBe(`${'a '.repeat(50)}[REDACTED:size-limit]`);
        expect(text).not.toContain(FAKE);
        expect(hits.at(-1)).toEqual({ ruleId: 'size-limit', range: [100, 100 + tail.length] });
    });

    test('a secret inside the scanned part of an over-long text is still redacted', () => {
        const input = `password=${FAKE} ${'x '.repeat(100)}`;
        const { text } = redactTextSync(input, { maxChars: 120 });
        expect(text.startsWith('password=[REDACTED:generic-keyword] ')).toBe(true);
        expect(text.endsWith('[REDACTED:size-limit]')).toBe(true);
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

    test('values beyond maxNodes are replaced', () => {
        const out = redactJsonValueSync([{ a: 1 }, { a: 2 }, { a: 3 }], { maxNodes: 2 }) as unknown[];
        expect(out[0]).toEqual({ a: 1 });
        expect(out[2]).toBe('[REDACTED:size-limit]');
    });

    test('strings beyond the maxChars budget are cut or replaced', () => {
        const out = redactJsonValueSync({ a: 'x'.repeat(60), b: `password=${FAKE}` }, { maxChars: 50 }) as {
            a: string;
            b: string;
        };
        expect(out.a).toBe(`${'x'.repeat(50)}[REDACTED:size-limit]`);
        expect(out.b).toBe('[REDACTED:size-limit]');
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
