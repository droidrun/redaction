/**
 * strict.test.ts — `mode: 'strict'` never returns text it did not scan: a failing
 * scanner, a text past the scan cap, a value past a limit, a value outside the JSON
 * model and an over-long key all become placeholders; the walker is iterative; and the
 * default stays `compat`. The cross-language cases are `spec/vectors/modes.json`.
 */
import { expect, test } from 'bun:test';
import { redactJsonValue, redactJsonValueSync, redactText, redactTextSync } from './index.js';

const SECRET = 'password=Zq9abcDEF123ghi_x';
const FAILING = async (): Promise<never> => {
    throw new Error('boom');
};

test('compat is the default: a failing scanner falls back to the sync rules', async () => {
    const result = await redactText(`hello ${SECRET}`, { detect: FAILING });
    expect(result.text).toBe('hello password=[REDACTED:generic-keyword]');
});

test('strict: a failing scanner replaces the whole text and reports the error class only', async () => {
    const events: Array<[string, Record<string, unknown>]> = [];
    const result = await redactText(`hello ${SECRET}`, {
        detect: FAILING,
        mode: 'strict',
        onEvent: (name, attrs) => void events.push([name, attrs]),
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(result).toEqual({ text: '[REDACTED:error]', hits: [{ ruleId: 'error', range: [0, 0] }] });
    expect(events).toEqual([['redaction.detect.failed', { errorName: 'Error' }]]);
});

test('strict: text past the scan cap keeps no unscanned rest', async () => {
    const filler = 'ab '.repeat(666_700);
    const text = `${filler} tail ${SECRET}`;
    const strict = await redactText(text, { mode: 'strict' });
    expect(strict.text.length).toBe(2_000_000 + '[REDACTED:size-limit]'.length);
    expect(strict.text.endsWith('ab[REDACTED:size-limit]')).toBe(true);
    expect(strict.text.includes('tail')).toBe(false);
    const compat = await redactText(text);
    expect(compat.text.endsWith(' tail password=[REDACTED:generic-keyword]')).toBe(true);
});

test('strict: a hit that straddles the scan cap is merged with the size-limit rest', async () => {
    const lead = 'x '.repeat(999_990);
    const text = `${lead}password=Zq9abcDEF123ghi_x and more`;
    const strict = await redactText(text, { mode: 'strict' });
    expect(strict.text.endsWith('[REDACTED:generic-keyword]')).toBe(true);
    expect(strict.text.length).toBeLessThan(lead.length + 40);
});

test('strict walker is iterative: 200000 levels do not overflow the stack', () => {
    let deep: unknown = 'x';
    for (let i = 0; i < 200_000; i++) deep = [deep];
    const out = redactJsonValueSync(deep, { mode: 'strict', maxDepth: 1_000_000 });
    let levels = 0;
    let cursor: unknown = out;
    while (Array.isArray(cursor)) {
        cursor = cursor[0];
        levels += 1;
    }
    expect([levels, cursor]).toEqual([200_000, 'x']);
});

test('strict: depth, nodes and characters past their limit become placeholders, never raw values', () => {
    const stats = { hits: [] as Array<{ ruleId: string }> };
    const out = redactJsonValueSync(
        { a: { b: { c: 'x' } }, list: [1, 2, 3, 4, 5], long: SECRET },
        { mode: 'strict', maxDepth: 2, maxNodes: 8, maxChars: 20, stats: stats as { hits: never[] } },
    );
    expect(out).toEqual({
        a: { b: '[REDACTED:depth-limit]' },
        list: [1, 2, 3, 4, '[REDACTED:size-limit]'],
        '[REDACTED:size-limit]': '[REDACTED:size-limit]',
    });
    expect(stats.hits.map((hit) => hit.ruleId)).toContain('depth-limit');
});

test('strict: values outside the JSON model and cycles are replaced', () => {
    const cycle: Record<string, unknown> = { a: 1 };
    cycle.self = cycle;
    expect(redactJsonValueSync(cycle, { mode: 'strict' })).toEqual({ a: 1, self: '[REDACTED:circular]' });
    const odd = redactJsonValueSync(
        { when: new Date(0), run: () => 1, sym: Symbol('s') },
        { mode: 'strict' },
    );
    expect(odd).toEqual({
        when: '[REDACTED:redaction-failed]',
        run: '[REDACTED:redaction-failed]',
        sym: '[REDACTED:redaction-failed]',
    });
});

test('strict: the same walk on the async entry scans each leaf with the full tier', async () => {
    const value = { a: [{ token: 'abc' }], note: `x ${SECRET}` };
    const sync = redactJsonValueSync(value, { mode: 'strict' });
    const asyncOut = await redactJsonValue(value, { hits: [] }, { mode: 'strict' });
    expect(asyncOut).toEqual(sync);
    expect(sync).toEqual({
        a: [{ token: '[REDACTED:key-context]' }],
        note: 'x password=[REDACTED:generic-keyword]',
    });
});

test('strict text on the sync entry is the compat result (it already fails closed)', () => {
    const text = `a ${SECRET} b`;
    expect(redactTextSync(text, { mode: 'strict' })).toEqual(redactTextSync(text));
});

test('strict: last4 is ignored, no hit carries a character of the text', async () => {
    const filler = 'ab '.repeat(666_700);
    const text = `${filler} tail ${SECRET}`;
    const strict = await redactText(text, { mode: 'strict', last4: true });
    expect(strict.text.endsWith('ab[REDACTED:size-limit]')).toBe(true);
    const keyed = await redactText('password: S0mmer2026!xTr0ub4dor', { mode: 'strict', last4: true });
    expect(keyed.text).toBe('password: [REDACTED:generic-keyword]');
});

test('strict: a text over maxChars is replaced whole before any scan', async () => {
    const strict = await redactText(`a ${SECRET}`, { mode: 'strict', maxChars: 10 });
    expect(strict).toEqual({
        text: '[REDACTED:size-limit]',
        hits: [{ ruleId: 'size-limit', range: [0, 28] }],
    });
    const fits = await redactText(`a ${SECRET}`, { mode: 'strict', maxChars: 28 });
    expect(fits.text).toBe('a password=[REDACTED:generic-keyword]');
    const huge = await redactText('x '.repeat(2_000_001), { mode: 'strict' });
    expect(huge.text).toBe('[REDACTED:size-limit]');
});

test('strict: a million hits in one value do not overflow the stack', () => {
    const value = Array.from({ length: 1_050_000 }, () => 'token=Zq9abcDE');
    const stats = { hits: [] as Array<{ ruleId: string }> };
    const limits = { mode: 'strict', maxChars: 30_000_000, maxNodes: 2_000_000 } as const;
    const out = redactJsonValueSync(value, { ...limits, stats: stats as { hits: never[] } }) as string[];
    expect(out[1_049_999]).toBe('token=[REDACTED:generic-keyword]');
    expect(stats.hits).toHaveLength(1_050_000);
}, 120_000);

const TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234';

test('strict scans strings under the default skip keys, sync and async; compat keeps them', async () => {
    const value = { id: TOKEN, type: `x ${SECRET}`, nested: { id: TOKEN } };
    const scanned = {
        id: '[REDACTED:github]',
        type: 'x password=[REDACTED:generic-keyword]',
        nested: { id: '[REDACTED:github]' },
    };
    expect(redactJsonValueSync(value, { mode: 'strict' })).toEqual(scanned);
    expect(await redactJsonValue(value, { hits: [] }, { mode: 'strict' })).toEqual(scanned);
    expect(redactJsonValueSync(value)).toEqual(value);
});

test('strict: a custom skip set scans too, and a skip key still exempts from key-context', () => {
    const out = redactJsonValueSync(
        { recordId: TOKEN, password: { id: 'plain', n: 1 } },
        { mode: 'strict', skipKeys: new Set(['recordId', 'id']) },
    );
    expect(out).toEqual({
        recordId: '[REDACTED:github]',
        password: { id: 'plain', n: '[REDACTED:key-context]' },
    });
});

test('strict: non-string primitives under a skip key are returned unchanged', () => {
    const value = { id: 7, type: null, flag: true };
    expect(redactJsonValueSync({ ...value, ok: false }, { mode: 'strict' })).toEqual({ ...value, ok: false });
});
