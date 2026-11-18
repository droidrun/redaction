/**
 * dotted-token.test.ts — the JWT rule is the linear scanner, and it finds exactly what
 * the plain expression `\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b` finds (which is
 * quadratic on `eyJ-eyJ-…`): same ranges on random strings built from its own
 * building blocks, and a time budget on the string that made the expression quadratic.
 */
import { expect, test } from 'bun:test';
import { redactTextSync } from './index.js';

const REFERENCE = /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/g;
const PIECES = [
    'eyJ',
    'a',
    'Z9',
    '-',
    '_',
    '.',
    ' ',
    'abcdefghij',
    'x-',
    '-x',
    '..',
    'é',
    '=',
    'eyJabcdefghijk',
    'abcdefghijk.',
    'eyJabcdefghijk.',
    'abcdefghijk-',
    '.abcdefghij',
];

function mulberry32(seed: number): () => number {
    let a = seed;
    return () => {
        a = (a + 0x6d2b79f5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

function expectedRedaction(text: string): string {
    return text.replace(REFERENCE, '[REDACTED:jwt]');
}

test('the scanner redacts what the plain expression matches, on 20000 random strings', () => {
    const rng = mulberry32(0x7a77ed);
    let withToken = 0;
    for (let i = 0; i < 20_000; i++) {
        const length = 3 + Math.floor(rng() * 8);
        const text = Array.from({ length }, () => PIECES[Math.floor(rng() * PIECES.length)]).join('');
        const expected = expectedRedaction(text);
        if (expected !== text) withToken += 1;
        if (redactTextSync(text).text !== expected) throw new Error(`case ${i}: ${JSON.stringify(text)}`);
    }
    expect(withToken).toBeGreaterThan(200);
});

test('a trailing hyphen is left out of the token, as the expression backtracks', () => {
    const token = 'eyJhbGciOiJIUzI1NiI.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT4fwpMeJf36-';
    expect(redactTextSync(`jwt ${token} end`).text).toBe('jwt [REDACTED:jwt]- end');
    expect(expectedRedaction(`jwt ${token} end`)).toBe('jwt [REDACTED:jwt]- end');
});

test('eyJ- repeated 100000 times stays linear', () => {
    const text = 'eyJ-'.repeat(100_000);
    const started = performance.now();
    expect(redactTextSync(text).text).toBe(text);
    expect(performance.now() - started).toBeLessThan(2000);
});
