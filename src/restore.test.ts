/**
 * restore.test.ts — `restoreRedacted(incoming, stored)`: a placeholder that
 * comes back keeps the stored value; everything else is what the client sent.
 */
import { describe, expect, test } from 'bun:test';
import { redactJsonValue, redactJsonValueSync, restoreRedacted } from './index.js';

const SECRET = 'Zk9-fakeMARKER_7q2x';

describe('strings', () => {
    test.each([
        '[REDACTED:key-context]',
        '[REDACTED:generic-keyword:4dor]',
        '[REDACTED]',
    ])('a whole placeholder %s keeps the stored string', (placeholder) => {
        expect(restoreRedacted({ a: placeholder }, { a: SECRET })).toEqual({ a: SECRET });
    });

    test('a string that contains a placeholder keeps the stored string whole', () => {
        const stored = { run: `curl -H "Authorization: Bearer ${SECRET}"` };
        const incoming = { run: 'curl -H "Authorization: Bearer [REDACTED:auth-header]"' };
        expect(restoreRedacted(incoming, stored)).toEqual(stored);
    });

    test('a string without a placeholder is the new value', () => {
        expect(restoreRedacted({ a: 'new' }, { a: SECRET })).toEqual({ a: 'new' });
    });

    test('a placeholder with no stored value behind it stays a placeholder (never invented)', () => {
        expect(restoreRedacted({ a: '[REDACTED:key-context]' }, {})).toEqual({ a: '[REDACTED:key-context]' });
        expect(restoreRedacted({ a: '[REDACTED:key-context]' }, { a: null })).toEqual({
            a: '[REDACTED:key-context]',
        });
        expect(restoreRedacted({ a: '[REDACTED:key-context]' }, { a: true })).toEqual({
            a: '[REDACTED:key-context]',
        });
    });

    test('text that only looks similar is not a placeholder', () => {
        for (const text of ['[REDACTED', 'REDACTED]', '[redacted]', '[REDACTED: x]']) {
            expect(restoreRedacted({ a: text }, { a: SECRET })).toEqual({ a: text });
        }
    });
});

describe('whole values replaced under a secret-named key', () => {
    test('a whole placeholder restores a stored number, object or array', () => {
        const stored = { pin: 1234, client_secret: { id: 1, v: 'x' }, tokens: ['a', 'b'] };
        const incoming = {
            pin: '[REDACTED:key-context]',
            client_secret: '[REDACTED:key-context]',
            tokens: '[REDACTED:key-context]',
        };
        expect(restoreRedacted(incoming, stored)).toEqual(stored);
    });

    test('a placeholder INSIDE a longer string does not restore a non-string', () => {
        expect(restoreRedacted({ a: 'x [REDACTED] y' }, { a: { b: 1 } })).toEqual({ a: 'x [REDACTED] y' });
    });
});

describe('structure', () => {
    test('new keys win, removed keys are gone, kept keys are restored', () => {
        const stored = { a: SECRET, b: SECRET, c: 'old' };
        const incoming = { a: '[REDACTED:key-context]', c: 'edited', d: 'added' };
        expect(restoreRedacted(incoming, stored)).toEqual({ a: SECRET, c: 'edited', d: 'added' });
    });

    test('nested objects and arrays are matched by key and index', () => {
        const stored = { steps: [{ with: { token: SECRET } }, { with: { token: 'other' } }] };
        const ph = '[REDACTED:key-context]';
        const incoming = {
            steps: [{ with: { token: ph } }, { with: { token: ph } }, { with: { token: 'brand-new' } }],
        };
        expect(restoreRedacted(incoming, stored)).toEqual({
            steps: [
                { with: { token: SECRET } },
                { with: { token: 'other' } },
                { with: { token: 'brand-new' } },
            ],
        });
    });

    test('a type change takes the incoming value', () => {
        expect(restoreRedacted({ a: { b: 1 } }, { a: 'str' })).toEqual({ a: { b: 1 } });
        expect(restoreRedacted({ a: [1] }, { a: { x: 1 } })).toEqual({ a: [1] });
    });

    test('does not mutate either argument', () => {
        const incoming = { a: '[REDACTED]', n: { b: '[REDACTED]' } };
        const stored = { a: SECRET, n: { b: SECRET } };
        const incomingCopy = structuredClone(incoming);
        const storedCopy = structuredClone(stored);
        restoreRedacted(incoming, stored);
        expect(incoming).toEqual(incomingCopy);
        expect(stored).toEqual(storedCopy);
    });

    test('keys named __proto__ or constructor are plain keys', () => {
        const incoming = JSON.parse('{"__proto__":"[REDACTED]","constructor":"[REDACTED]"}');
        const stored = JSON.parse('{"__proto__":"s1","constructor":"s2"}');
        const out = restoreRedacted(incoming, stored) as Record<string, unknown>;
        expect(Object.keys(out)).toEqual(['__proto__', 'constructor']);
        expect(Object.getOwnPropertyDescriptor(out, '__proto__')?.value).toBe('s1');
        expect(Object.getOwnPropertyDescriptor(out, 'constructor')?.value).toBe('s2');
        expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    });

    test('top-level values', () => {
        expect(restoreRedacted('[REDACTED]', SECRET)).toBe(SECRET);
        expect(restoreRedacted(['[REDACTED]', 'x'], [SECRET, 'y'])).toEqual([SECRET, 'x']);
        expect(restoreRedacted(5, 6)).toBe(5);
        expect(restoreRedacted(null, { a: 1 })).toBeNull();
    });
});

describe('round trip with both redactors', () => {
    const stored = {
        name: 'routine',
        steps: [
            {
                type: 'http',
                with: { url: 'https://x.test/?token=abc123&x=1', headers: { 'X-Api-Key': SECRET } },
            },
            { type: 'script', with: { code: `curl -H "Authorization: Bearer ${SECRET}"`, pin: 4242 } },
        ],
        nested: { password: SECRET, list: ['plain', `password=${SECRET}`], flag: true, none: null },
    };

    test('restore(redactSync(x), x) == x', () => {
        const redacted = redactJsonValueSync(stored);
        expect(JSON.stringify(redacted)).not.toContain(SECRET);
        expect(restoreRedacted(redacted, stored)).toEqual(stored);
    });

    test('restore(redactAsync(x), x) == x', async () => {
        const redacted = await redactJsonValue(stored, { hits: [] });
        expect(JSON.stringify(redacted)).not.toContain(SECRET);
        expect(restoreRedacted(redacted, stored)).toEqual(stored);
    });

    test('a read-modify-write that edits one field keeps the secrets', () => {
        const redacted = redactJsonValueSync(stored) as typeof stored;
        redacted.name = 'renamed';
        expect(restoreRedacted(redacted, stored)).toEqual({ ...stored, name: 'renamed' });
    });

    test('limit placeholders restore the subtree they replaced', () => {
        const deep = { a: { b: { c: { password: SECRET } } } };
        const redacted = redactJsonValueSync(deep, { maxDepth: 2 });
        expect(redacted).toEqual({ a: { b: '[REDACTED:depth-limit]' } });
        expect(restoreRedacted(redacted, deep)).toEqual(deep);
    });
});
