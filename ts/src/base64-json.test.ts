/**
 * base64-json.test.ts — the 1Password check (SPEC 5.7) decodes and parses with its own code, so the three languages
 * agree. Here that code is held against this runtime's `atob` and `JSON.parse` on seeded random strings.
 */
import { expect, test } from 'bun:test';
import { mulberry32, pick } from '../../tools/corpus/rng.ts';
import { isBase64Json, isJsonContainer } from './algorithms/base64-json.js';

const BASE64_UNITS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const JSON_UNITS = [
    '{',
    '}',
    '[',
    ']',
    '"',
    ':',
    ',',
    '0',
    '1',
    '9',
    '-',
    '.',
    'e',
    'E',
    '+',
    'true',
    'false',
    'null',
    'nul',
    'a',
    '\\',
    'u',
    '00e9',
    ' ',
    '\t',
    '\n',
    '\r',
    ' ',
    '\u0001',
    'é',
    '/',
    'b',
    'f',
    'n',
    'r',
    't',
    'x',
];

function randomFrom(rng: () => number, units: readonly string[], max: number): string {
    let out = '';
    for (let count = Math.floor(rng() * max); count > 0; count--) out += pick(rng, units);
    return out;
}

function runtimeBytes(input: string): number[] | undefined {
    try {
        return [...atob(input)].map((char) => char.charCodeAt(0));
    } catch {
        return undefined;
    }
}

function runtimeIsContainer(bytes: number[]): boolean {
    try {
        const value: unknown = JSON.parse(String.fromCharCode(...bytes));
        return typeof value === 'object' && value !== null;
    } catch {
        return false;
    }
}

function runtimeIsBase64Json(input: string): boolean {
    const bytes = runtimeBytes(input);
    return bytes !== undefined && runtimeIsContainer(bytes);
}

/** A base64 text of a random JSON-like text, then cut, padded or with one unit changed. */
function randomBase64(rng: () => number): string {
    const head = pick(rng, ['', '{', '[', '{"a":', '[1,']);
    const tail = pick(rng, ['', '}', ']']);
    const encoded = btoa(head + randomFrom(rng, JSON_UNITS, 12) + tail);
    const at = Math.floor(rng() * encoded.length);
    const unit = pick(rng, [...BASE64_UNITS]);
    return pick(rng, [
        encoded,
        encoded.replace(/=+$/, ''),
        `${encoded}=`,
        encoded.slice(0, at),
        encoded.slice(0, at) + unit + encoded.slice(at + 1),
    ]);
}

test('the base64 JSON check says what atob and JSON.parse say, and fails where atob throws', () => {
    const rng = mulberry32(1);
    const differing: string[] = [];
    let accepted = 0;
    for (let i = 0; i < 40000; i++) {
        const input = i % 2 === 0 ? randomFrom(rng, [...BASE64_UNITS], 14) : randomBase64(rng);
        const mine = isBase64Json(input);
        if (mine) accepted += 1;
        if (mine !== runtimeIsBase64Json(input)) differing.push(input);
    }
    expect(differing.slice(0, 10)).toEqual([]);
    expect(accepted).toBeGreaterThan(100);
});

test('the JSON check says what JSON.parse says for an object or an array', () => {
    const rng = mulberry32(2);
    const differing: string[] = [];
    let accepted = 0;
    for (let i = 0; i < 60000; i++) {
        const text = `${pick(rng, ['', '{', '[', '{"a":', '[1,'])}${randomFrom(rng, JSON_UNITS, 12)}${pick(rng, ['', '}', ']'])}`;
        const bytes = [...text].map((char) => char.charCodeAt(0) & 0xff);
        const mine = isJsonContainer(bytes);
        if (mine) accepted += 1;
        if (mine !== runtimeIsContainer(bytes)) differing.push(text);
    }
    expect(differing.slice(0, 10)).toEqual([]);
    expect(accepted).toBeGreaterThan(200);
});

test('a deep container does not need recursion', () => {
    const depth = 2000;
    const bytes = [...`${'['.repeat(depth)}${']'.repeat(depth)}`].map((char) => char.charCodeAt(0));
    expect(isJsonContainer(bytes)).toBe(true);
    expect(isJsonContainer(bytes.slice(0, -1))).toBe(false);
});

test('the token check on whole tokens', () => {
    const encode = (text: string): string => Buffer.from(text, 'latin1').toString('base64');
    expect(isBase64Json(encode('{"a":1}'))).toBe(true);
    expect(isBase64Json(encode('[1]'))).toBe(true);
    expect(isBase64Json(encode('"a"'))).toBe(false);
    expect(isBase64Json(encode('{"a":1,}'))).toBe(false);
    expect(isBase64Json(`${encode('{"a":1}')}A`)).toBe(false);
});
