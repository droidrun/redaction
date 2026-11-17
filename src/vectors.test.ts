/**
 * vectors.test.ts — the conformance loader. `vectors/*.json` hold the cases
 * every implementation of this redaction (this package, the consumers' tests,
 * later the Go and Python ports) must agree on:
 *
 *   { "description": "...", "cases": [ { name, input, expected } ] }
 *
 * `expected` is the output of BOTH entry points; a case where the async path
 * is more specific (a scanner finds it under another rule id) carries
 * `expectedSync` and `expectedAsync` instead.
 *
 * A string `input` is run through `redactTextSync` / `redactText`; any other
 * JSON value through `redactJsonValueSync` / `redactJsonValue`.
 */
import { describe, expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { redactJsonValue, redactJsonValueSync, redactText, redactTextSync } from './index.js';

type VectorCase = {
    name: string;
    input: unknown;
    expected?: unknown;
    expectedSync?: unknown;
    expectedAsync?: unknown;
};
type VectorFile = { description: string; cases: VectorCase[] };

const VECTORS_DIR = join(import.meta.dir, '..', 'vectors');
const REQUIRED_FILES = [
    'auth-headers', 'base64', 'false-positives', 'key-formats', 'key-names', 'keywords', 'nested-json',
    'url-query',
];

function loadVectors(): Array<[string, VectorFile]> {
    return readdirSync(VECTORS_DIR)
        .filter((file) => file.endsWith('.json'))
        .sort()
        .map((file) => {
            const content = readFileSync(join(VECTORS_DIR, file), 'utf8');
            return [file.replace(/\.json$/, ''), JSON.parse(content) as VectorFile];
        });
}

async function runAsync(input: unknown): Promise<unknown> {
    if (typeof input === 'string') return (await redactText(input)).text;
    return redactJsonValue(input, { hits: [] });
}

function runSync(input: unknown): unknown {
    if (typeof input === 'string') return redactTextSync(input).text;
    return redactJsonValueSync(input);
}

const vectors = loadVectors();

function expectedFor(vector: VectorCase, entry: 'sync' | 'async'): unknown {
    if (Object.hasOwn(vector, 'expected')) return vector.expected;
    return entry === 'sync' ? vector.expectedSync : vector.expectedAsync;
}

test('every case has `expected` or both `expectedSync` and `expectedAsync`, never a redundant pair', () => {
    for (const [, file] of vectors) {
        for (const vector of file.cases) {
            const shorthand = Object.hasOwn(vector, 'expected');
            const pair = Object.hasOwn(vector, 'expectedSync') && Object.hasOwn(vector, 'expectedAsync');
            expect(shorthand !== pair).toBe(true);
            if (pair) expect(vector.expectedSync).not.toEqual(vector.expectedAsync);
        }
    }
});

test('every category of the conformance set is present and non-empty', () => {
    expect(vectors.map(([name]) => name)).toEqual(REQUIRED_FILES);
    for (const [, file] of vectors) {
        expect(file.cases.length).toBeGreaterThan(0);
    }
});

test('case names are unique within a file', () => {
    for (const [, file] of vectors) {
        const names = file.cases.map((c) => c.name);
        expect(new Set(names).size).toBe(names.length);
    }
});

for (const [fileName, file] of vectors) {
    describe(`vectors/${fileName}`, () => {
        for (const vector of file.cases) {
            test(`sync: ${vector.name}`, () => {
                expect(runSync(vector.input)).toEqual(expectedFor(vector, 'sync'));
            });

            test(`async: ${vector.name}`, async () => {
                expect(await runAsync(vector.input)).toEqual(expectedFor(vector, 'async'));
            });

            test(`idempotent on both entry points: ${vector.name}`, async () => {
                const sync = expectedFor(vector, 'sync');
                const async = expectedFor(vector, 'async');
                expect(runSync(sync)).toEqual(sync);
                expect(await runAsync(async)).toEqual(async);
            });
        }
    });
}
