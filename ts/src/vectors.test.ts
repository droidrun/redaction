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
import { expandGen } from '../../tools/corpus/types.ts';
import { redactJsonValue, redactJsonValueSync, redactText, redactTextSync } from './index.js';

type Parts = { parts: Array<[string, number]> };
type VectorCase = {
    name: string;
    input?: unknown;
    inputGen?: Parts;
    mode?: 'compat' | 'strict';
    opts?: { maxChars?: number; maxDepth?: number; maxNodes?: number };
    expected?: unknown;
    expectedSync?: unknown;
    expectedAsync?: unknown;
    expectedGenSync?: Parts;
    expectedGenAsync?: Parts;
};
type VectorFile = { description: string; tier?: 'full'; cases: VectorCase[] };

const VECTORS_DIR = join(import.meta.dir, '..', '..', 'spec', 'vectors');
const REQUIRED_FILES = [
    'auth-headers', 'base64', 'entropy', 'false-positives', 'full', 'key-formats', 'key-names', 'keywords', 'modes',
    'nested-json', 'url-query',
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

function inputOf(vector: VectorCase): unknown {
    return vector.inputGen === undefined ? vector.input : expandGen(vector.inputGen);
}

async function runAsync(vector: VectorCase): Promise<unknown> {
    const input = inputOf(vector);
    const limits = { mode: vector.mode, ...vector.opts };
    if (typeof input === 'string') return (await redactText(input, limits)).text;
    return redactJsonValue(input, { hits: [] }, limits);
}

function runSync(vector: VectorCase): unknown {
    const input = inputOf(vector);
    const limits = { mode: vector.mode, ...vector.opts };
    if (typeof input === 'string') return redactTextSync(input, limits).text;
    return redactJsonValueSync(input, limits);
}

/** Equal values and equal key order (SPEC section 14: object key order is part of the output). */
function expectSame(actual: unknown, expected: unknown): void {
    expect(actual).toEqual(expected);
    expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
}

const vectors = loadVectors();

function expectedFor(vector: VectorCase, entry: 'sync' | 'async'): unknown {
    if (Object.hasOwn(vector, 'expected')) return vector.expected;
    const generated = entry === 'sync' ? vector.expectedGenSync : vector.expectedGenAsync;
    if (generated !== undefined) return expandGen(generated);
    return entry === 'sync' ? vector.expectedSync : vector.expectedAsync;
}

test('every case has `expected` or both `expectedSync` and `expectedAsync`, never a redundant pair', () => {
    for (const [, file] of vectors) {
        for (const vector of file.cases) {
            const shorthand = Object.hasOwn(vector, 'expected');
            const generated = vector.expectedGenSync !== undefined && vector.expectedGenAsync !== undefined;
            const pair = Object.hasOwn(vector, 'expectedSync') && Object.hasOwn(vector, 'expectedAsync');
            expect([shorthand, generated, pair].filter(Boolean)).toHaveLength(1);
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
                expectSame(runSync(vector), expectedFor(vector, 'sync'));
            });

            test(`async: ${vector.name}`, async () => {
                expectSame(await runAsync(vector), expectedFor(vector, 'async'));
            });

            test(`idempotent on both entry points: ${vector.name}`, async () => {
                const sync = expectedFor(vector, 'sync');
                const async = expectedFor(vector, 'async');
                expect(runSync({ name: vector.name, input: sync, mode: vector.mode })).toEqual(sync);
                expect(await runAsync({ name: vector.name, input: async, mode: vector.mode })).toEqual(async);
            });
        }
    });
}
