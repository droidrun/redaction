/**
 * restore.test.ts — `restoreRedacted(incoming, stored)`: a placeholder that
 * comes back keeps the stored value only where that is safe (matching item,
 * unchanged siblings, matching string segments); everything else is a conflict.
 */
import { describe, expect, test } from 'bun:test';
import { redactJsonValue, redactJsonValueSync, restoreRedacted } from './index.js';

const SECRET = 'Zk9-fakeMARKER_7q2x';
const PH = '[REDACTED:key-context]';

const restore = (incoming: unknown, stored: unknown) => restoreRedacted(incoming, stored);

describe('strings', () => {
    test.each([PH, '[REDACTED:generic-keyword:4dor]', '[REDACTED]', '[REDACTED:last4:a b]'])(
        'a whole placeholder %s keeps the stored string',
        (placeholder) => {
            const out = restore({ a: placeholder }, { a: SECRET });
            expect(out).toEqual({ value: { a: SECRET }, conflicts: [] });
        },
    );

    test('a string that contains a placeholder keeps the stored string if its literals match', () => {
        const stored = { run: `curl -H "Authorization: Bearer ${SECRET}" https://x.test` };
        const incoming = { run: 'curl -H "Authorization: Bearer [REDACTED:auth-header]" https://x.test' };
        expect(restore(incoming, stored)).toEqual({ value: stored, conflicts: [] });
    });

    test('edited text around a placeholder is a conflict, the placeholder stays', () => {
        const stored = { run: `curl -H "Authorization: Bearer ${SECRET}" https://good.test` };
        const incoming = { run: 'curl -H "Authorization: Bearer [REDACTED:auth-header]" https://evil.test' };
        expect(restore(incoming, stored)).toEqual({ value: incoming, conflicts: ['$.run'] });
    });

    test('literals in the wrong order, a missing prefix or suffix, are conflicts', () => {
        const stored = { a: `one ${SECRET} two ${SECRET} three` };
        const cases = [
            'two [REDACTED] one [REDACTED] three',
            'zero one [REDACTED] two [REDACTED] three',
            'one [REDACTED] two [REDACTED] three four',
        ];
        for (const text of cases) {
            expect(restore({ a: text }, stored).conflicts).toEqual(['$.a']);
        }
        expect(restore({ a: 'one [REDACTED] two [REDACTED] three' }, stored).conflicts).toEqual([]);
    });

    test('a string without a placeholder is the new value', () => {
        expect(restore({ a: 'new' }, { a: SECRET })).toEqual({ value: { a: 'new' }, conflicts: [] });
    });

    test('a placeholder with no stored value behind it stays and is a conflict (never invented)', () => {
        expect(restore({ a: PH }, {})).toEqual({ value: { a: PH }, conflicts: ['$.a'] });
        expect(restore({ a: PH }, { a: null })).toEqual({ value: { a: PH }, conflicts: ['$.a'] });
        expect(restore({ a: PH }, { a: true })).toEqual({ value: { a: PH }, conflicts: ['$.a'] });
    });

    test('text that only looks similar is not a placeholder', () => {
        for (const text of ['[REDACTED', 'REDACTED]', '[redacted]', '[REDACTED: x]']) {
            expect(restore({ a: text }, { a: SECRET })).toEqual({ value: { a: text }, conflicts: [] });
        }
    });
});

describe('whole values under a legacy placeholder', () => {
    test('a whole placeholder restores a stored number, object or array', () => {
        const stored = { pin: 1234, client_secret: { id: 1, v: 'x' }, tokens: ['a', 'b'] };
        const incoming = { pin: PH, client_secret: PH, tokens: PH };
        expect(restore(incoming, stored)).toEqual({ value: stored, conflicts: [] });
    });

    test('a placeholder INSIDE a longer string does not restore a non-string', () => {
        const out = restore({ a: 'x [REDACTED] y' }, { a: { b: 1 } });
        expect(out).toEqual({ value: { a: 'x [REDACTED] y' }, conflicts: ['$.a'] });
    });
});

describe('structure', () => {
    test('new keys win, removed keys are gone, kept keys are restored', () => {
        const stored = { token: SECRET, apiKey: SECRET, password: 'old' };
        const incoming = { token: PH, password: 'edited', secret: 'added' };
        const expected = { token: SECRET, password: 'edited', secret: 'added' };
        expect(restore(incoming, stored)).toEqual({ value: expected, conflicts: [] });
    });

    test('a type change takes the incoming value', () => {
        expect(restore({ a: { b: 1 } }, { a: 'str' }).value).toEqual({ a: { b: 1 } });
        expect(restore({ a: [1] }, { a: { x: 1 } }).value).toEqual({ a: [1] });
    });

    test('does not mutate either argument', () => {
        const incoming = { a: '[REDACTED]', n: { b: '[REDACTED]' } };
        const stored = { a: SECRET, n: { b: SECRET } };
        const incomingCopy = structuredClone(incoming);
        const storedCopy = structuredClone(stored);
        restore(incoming, stored);
        expect(incoming).toEqual(incomingCopy);
        expect(stored).toEqual(storedCopy);
    });

    test('keys named __proto__ or constructor are plain keys', () => {
        const incoming = JSON.parse('{"__proto__":"[REDACTED]","constructor":"[REDACTED]"}');
        const stored = JSON.parse('{"__proto__":"s1","constructor":"s2"}');
        const out = restore(incoming, stored).value as Record<string, unknown>;
        expect(Object.keys(out)).toEqual(['__proto__', 'constructor']);
        expect(Object.getOwnPropertyDescriptor(out, '__proto__')?.value).toBe('s1');
        expect(Object.getOwnPropertyDescriptor(out, 'constructor')?.value).toBe('s2');
        expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    });

    test('top-level values', () => {
        expect(restore('[REDACTED]', SECRET)).toEqual({ value: SECRET, conflicts: [] });
        expect(restore(5, 6)).toEqual({ value: 5, conflicts: [] });
        expect(restore(null, { a: 1 })).toEqual({ value: null, conflicts: [] });
    });
});

describe('arrays: matched by identity, never by a shifted index', () => {
    const step = (id: string, token: string, extra: Record<string, unknown> = {}) => ({
        id,
        url: `https://${id}.test`,
        token,
        ...extra,
    });
    const stored = [step('a', 'tok-a'), step('b', 'tok-b'), step('c', 'tok-c')];
    const redacted = (items: unknown[]) => items.map((item) => ({ ...(item as object), token: PH }));

    test('unchanged array restores everything', () => {
        expect(restore(redacted(stored), stored)).toEqual({ value: stored, conflicts: [] });
    });

    test('delete: the right secret stays with the right item', () => {
        const incoming = redacted([stored[0], stored[2]]);
        expect(restore(incoming, stored)).toEqual({ value: [stored[0], stored[2]], conflicts: [] });
    });

    test('insert: the new item has no stored secret, a placeholder there is a conflict', () => {
        const added = { id: 'n', url: 'https://n.test', token: PH };
        const incoming = [...redacted(stored.slice(0, 1)), added, ...redacted(stored.slice(1))];
        const out = restore(incoming, stored);
        expect(out.value).toEqual([stored[0], added, stored[1], stored[2]]);
        expect(out.conflicts).toEqual(['$[1].token']);
    });

    test('reorder: secrets follow their ids', () => {
        const incoming = redacted([stored[2], stored[0], stored[1]]);
        const expected = [stored[2], stored[0], stored[1]];
        expect(restore(incoming, stored)).toEqual({ value: expected, conflicts: [] });
    });

    test('duplicate ids are ambiguous: nothing is restored, every placeholder is a conflict', () => {
        const dup = [step('x', 'first'), step('x', 'second')];
        const out = restore(redacted(dup), dup);
        expect(out.value).toEqual(redacted(dup));
        expect(out.conflicts).toEqual(['$[0].token', '$[1].token']);
        expect(restore(redacted([dup[1]]), dup).conflicts).toEqual(['$[0].token']);
    });

    test('identify option', () => {
        const items = [{ name: 'a', token: 't1' }, { name: 'b', token: 't2' }];
        const incoming = [{ name: 'b', token: PH }, { name: 'a', token: PH }];
        const out = restoreRedacted(incoming, items, { identify: (item) => (item as { name: string }).name });
        expect(out).toEqual({ value: [items[1], items[0]], conflicts: [] });
    });

    test('no identity: index match only when the length is unchanged', () => {
        const items = [{ token: 't0', note: 'n' }, { token: 't1', note: 'm' }];
        const same = restore([{ token: PH, note: 'n' }, { token: PH, note: 'm' }], items);
        expect(same).toEqual({ value: items, conflicts: [] });
        const shorter = restore([{ token: PH, note: 'm' }], items);
        expect(shorter.value).toEqual([{ token: PH, note: 'm' }]);
        expect(shorter.conflicts).toEqual(['$[0].token']);
    });

    test('strings in an array: index match only when the length is unchanged', () => {
        const strings = ['a', SECRET, 'c'];
        expect(restore(['a', PH, 'c'], strings)).toEqual({ value: strings, conflicts: [] });
        expect(restore(['c', PH], strings).conflicts).toEqual(['$[1]']);
        expect(restore(['a', PH, 'edited'], strings).conflicts).toEqual([]);
        expect(restore(['a', PH], strings).conflicts).toEqual(['$[1]']);
    });
});

describe('threat model: editors are secret owners', () => {
    const stored = {
        url: 'https://a.test',
        headers: { Authorization: 'Bearer SECRET', accept: 'json' },
    };

    test('a changed sibling url does NOT block restore (documented contract)', () => {
        const incoming = { url: 'https://other.test', headers: { Authorization: PH, accept: 'json' } };
        expect(restore(incoming, stored)).toEqual({
            value: { url: 'https://other.test', headers: stored.headers },
            conflicts: [],
        });
    });

    test('added and removed siblings do not block either', () => {
        const base = { url: 'https://a.test', method: 'GET', token: SECRET };
        expect(restore({ url: base.url, token: PH }, base)).toEqual({
            value: { url: base.url, token: SECRET },
            conflicts: [],
        });
        expect(restore({ ...base, extra: 1, token: PH }, base).conflicts).toEqual([]);
    });

    test('a changed field in the same step does not block, a moved item still does', () => {
        const steps = [{ id: 's1', url: 'https://a.test', token: SECRET }];
        const edited = [{ id: 's1', url: 'https://b.test', token: PH }];
        expect(restore(edited, steps).conflicts).toEqual([]);
        const moved = [{ id: 's2', url: 'https://a.test', token: PH }];
        expect(restore(moved, steps).conflicts).toEqual(['$[0].token']);
    });

    test('a secret is never moved to another path', () => {
        const out = restore({ other: PH, token: SECRET }, { token: SECRET });
        expect(out).toEqual({ value: { other: PH, token: SECRET }, conflicts: ['$.other'] });
    });

    test('a stored (different) placeholder, null or boolean is not a secret to restore', () => {
        for (const behind of ['[REDACTED]', null, true, false, undefined]) {
            const out = restore({ a: PH }, { a: behind });
            expect(out).toEqual({ value: { a: PH }, conflicts: ['$.a'] });
        }
    });
});

describe('round trip with both redactors', () => {
    const stored = {
        name: 'routine',
        steps: [
            {
                id: 's1',
                type: 'http',
                with: { url: 'https://x.test/?token=abc123&x=1', headers: { 'X-Api-Key': SECRET } },
            },
            {
                id: 's2',
                type: 'script',
                with: { code: `curl -H "Authorization: Bearer ${SECRET}"`, pin: 4242 },
            },
        ],
        nested: { password: SECRET, list: ['plain', `password=${SECRET}`], flag: true, none: null },
    };

    test('restore(redactSync(x), x) == x', () => {
        const redacted = redactJsonValueSync(stored);
        expect(JSON.stringify(redacted)).not.toContain(SECRET);
        expect(restore(redacted, stored)).toEqual({ value: stored, conflicts: [] });
    });

    test('restore(redactAsync(x), x) == x', async () => {
        const redacted = await redactJsonValue(stored, { hits: [] });
        expect(JSON.stringify(redacted)).not.toContain(SECRET);
        expect(restore(redacted, stored)).toEqual({ value: stored, conflicts: [] });
    });

    test('a read-modify-write that edits one field keeps the secrets', () => {
        const redacted = redactJsonValueSync(stored) as typeof stored;
        redacted.name = 'renamed';
        expect(restore(redacted, stored)).toEqual({ value: { ...stored, name: 'renamed' }, conflicts: [] });
    });

    test('limit placeholders restore the subtree they replaced', () => {
        const deep = { a: { b: { c: { password: SECRET } } } };
        const redacted = redactJsonValueSync(deep, { maxDepth: 2 });
        expect(redacted).toEqual({ a: { b: '[REDACTED:depth-limit]' } });
        expect(restore(redacted, deep)).toEqual({ value: deep, conflicts: [] });
    });
});

describe('round trip of keys redacted in strict or with pii', () => {
    const emails = { 'bob@example.com': { n: 1 }, 'alice@example.com': { n: 2 } };
    const tokens = { 'token=hunter2': 'v', dr_sk_first1: 'w' };

    test('keys that hold emails come back, sync and async', async () => {
        const options = { pii: true } as const;
        const sync = redactJsonValueSync(emails, options);
        expect(Object.keys(sync as object)).toEqual(['[REDACTED:email]', '[REDACTED:email#2]']);
        expect(restore(sync, emails)).toEqual({ value: emails, conflicts: [] });
        const async = await redactJsonValue(emails, { hits: [] }, options);
        expect(restore(async, emails)).toEqual({ value: emails, conflicts: [] });
    });

    test('keys that only strict redacts come back, sync and async', async () => {
        const options = { mode: 'strict' } as const;
        const sync = redactJsonValueSync(tokens, options);
        const names = ['token=[REDACTED:generic-keyword]', '[REDACTED:platform-key]'];
        expect(Object.keys(sync as object)).toEqual(names);
        expect(restore(sync, tokens)).toEqual({ value: tokens, conflicts: [] });
        const async = await redactJsonValue(tokens, { hits: [] }, options);
        expect(restore(async, tokens)).toEqual({ value: tokens, conflicts: [] });
    });

    test('strict and pii together restore keys of both kinds', () => {
        const stored = { 'bob@example.com': 1, 'token=hunter2': 2 };
        const redacted = redactJsonValueSync(stored, { mode: 'strict', pii: true });
        expect(restore(redacted, stored)).toEqual({ value: stored, conflicts: [] });
    });

    test('a placeholder key that two stored keys could stand for is a conflict, never a guess', () => {
        const stored = { 'token=12345678': 'valueA', 'token=Abc123xyZQ': 'valueB' };
        const redacted = redactJsonValueSync(stored, { mode: 'strict' });
        const out = restore(redacted, stored);
        const placeholderKey = '$["token=[REDACTED:generic-keyword]"]';
        expect(out.conflicts).toEqual([placeholderKey, placeholderKey]);
        expect(out.value).toEqual({
            'token=[REDACTED:generic-keyword]': '[REDACTED:key-context]',
            'token=Abc123xyZQ': 'valueB',
        });
    });
});
