/**
 * place-key.test.ts — key collisions (SPEC 8, L-P): no value is lost; the first key keeps the plain
 * placeholder key, the next ones get `#2`, `#3` inside the brackets; the numbered form is a placeholder.
 */
import { describe, expect, test } from 'bun:test';
import { placeKey, type KeySlots } from './place-key.js';
import { PLACEHOLDER_RE } from './placeholder.js';
import { restoreRedacted } from './restore.js';

function place(entries: Array<[string, unknown]>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    const slots: KeySlots = new Map();
    for (const [key, value] of entries) placeKey(out, slots, key, value);
    return out;
}

describe('placeKey', () => {
    test('rule placeholders that collide are numbered in order', () => {
        const out = place([
            ['[REDACTED:npm]', 1],
            ['[REDACTED:npm]', 2],
            ['[REDACTED:npm]', 3],
        ]);
        expect(Object.entries(out)).toEqual([
            ['[REDACTED:npm]', 1],
            ['[REDACTED:npm#2]', 2],
            ['[REDACTED:npm#3]', 3],
        ]);
    });

    test('a number whose key exists is skipped', () => {
        const out = place([
            ['[REDACTED:npm]', 1],
            ['[REDACTED:npm#2]', 'x'],
            ['[REDACTED:npm]', 2],
        ]);
        expect(Object.entries(out)).toEqual([
            ['[REDACTED:npm]', 1],
            ['[REDACTED:npm#2]', 'x'],
            ['[REDACTED:npm#3]', 2],
        ]);
    });

    test('a key that is no rule placeholder keeps the old rule: the later value wins, same position', () => {
        const out = place([
            ['a [REDACTED:npm] b', 1],
            ['other', 2],
            ['a [REDACTED:npm] b', 3],
        ]);
        expect(Object.entries(out)).toEqual([
            ['a [REDACTED:npm] b', 3],
            ['other', 2],
        ]);
        expect(
            Object.entries(
                place([
                    ['[REDACTED]', 1],
                    ['[REDACTED]', 2],
                ]),
            ),
        ).toEqual([['[REDACTED]', 2]]);
        expect(
            Object.entries(
                place([
                    ['[REDACTED:a:b]', 1],
                    ['[REDACTED:a:b]', 2],
                ]),
            ),
        ).toEqual([['[REDACTED:a:b]', 2]]);
    });

    test('the numbered key is a placeholder', () => {
        expect(PLACEHOLDER_RE.test('[REDACTED:npm#2]')).toBe(true);
    });
});

describe('restoreRedacted with numbered placeholders', () => {
    test('a numbered placeholder value restores like the plain one', () => {
        for (const placeholder of ['[REDACTED:npm]', '[REDACTED:npm#2]']) {
            const restored = restoreRedacted({ a: placeholder }, { a: 'secret-value-1' });
            expect(restored).toEqual({ value: { a: 'secret-value-1' }, conflicts: [] });
        }
    });

    test('a numbered placeholder inside a text restores like the plain one', () => {
        const restored = restoreRedacted({ a: 'x [REDACTED:npm#2] y' }, { a: 'x secret y' });
        expect(restored).toEqual({ value: { a: 'x secret y' }, conflicts: [] });
    });

    test('a numbered placeholder with nothing behind it stays a conflict, like the plain one', () => {
        for (const placeholder of ['[REDACTED:npm]', '[REDACTED:npm#2]']) {
            expect(restoreRedacted({ a: placeholder }, {}).conflicts).toEqual(['$.a']);
        }
    });
});
