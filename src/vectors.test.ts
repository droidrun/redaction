/**
 * vectors.test.ts — the conformance loader. `vectors/*.json` hold the cases
 * every implementation of this redaction (this package, the consumers' tests,
 * later the Go and Python ports) must agree on:
 *
 *   { "description": "...", "cases": [ { name, input, expectedSync, expectedAsync } ] }
 *
 * A string `input` is run through `redactTextSync` / `redactText`; any other
 * JSON value through `redactJsonValueSync` / `redactJsonValue`.
 */
import { describe, expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { redactJsonValue, redactJsonValueSync, redactText, redactTextSync } from './index.js';

type VectorCase = { name: string; input: unknown; expectedSync: unknown; expectedAsync: unknown };
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
                expect(runSync(vector.input)).toEqual(vector.expectedSync);
            });

            test(`async: ${vector.name}`, async () => {
                expect(await runAsync(vector.input)).toEqual(vector.expectedAsync);
            });

            test(`idempotent on both entry points: ${vector.name}`, async () => {
                expect(runSync(vector.expectedSync)).toEqual(vector.expectedSync);
                expect(await runAsync(vector.expectedAsync)).toEqual(vector.expectedAsync);
            });
        }
    });
}
