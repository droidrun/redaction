/**
 * golden.test.ts — the rules moved from code into the spec without changing a byte of
 * output. `spec/corpus/golden-b12879a.json.gz` holds what the unchanged package (commit
 * b12879a) returned for the seeded corpus (`tools/corpus`: fuzz families, every vector input,
 * the JS whitespace set, case-fold and astral characters, lone surrogates, adversarial prefixes
 * before every rule, integer-like keys, key collisions, cases crossing every cap) on all four
 * entry points, and for the behaviour probes (`last4`, `detect`, `onEvent`, failures, values
 * that are not JSON, exported constants and helpers). Current output and hits must equal it.
 */
import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { runBehaviors } from '../../tools/corpus/behaviors.ts';
import { replayCase } from '../../tools/corpus/replay.ts';
import type { GoldenFile } from '../../tools/corpus/types.ts';
import * as api from './index.js';

const GOLDEN_PATH = join(import.meta.dir, '..', '..', 'spec', 'corpus', 'golden-b12879a.json.gz');
const GOLDEN = JSON.parse(gunzipSync(readFileSync(GOLDEN_PATH)).toString('utf8')) as GoldenFile;

test('the corpus holds at least 5000 cases', () => {
    expect(GOLDEN.cases.length).toBe(GOLDEN.count);
    expect(GOLDEN.count).toBeGreaterThanOrEqual(5000);
});

test('every corpus case gives the recorded output and hits, sync and async', async () => {
    const differing: string[] = [];
    for (const item of GOLDEN.cases) {
        const now = await replayCase(api as never, item);
        const same =
            JSON.stringify(now.sync) === JSON.stringify(item.sync) &&
            JSON.stringify(now.async) === JSON.stringify(item.async);
        if (!same) differing.push(item.id);
    }
    expect(differing).toEqual([]);
}, 120_000);

test('every behaviour probe gives the recorded result', async () => {
    const now = (await runBehaviors(api as never)) as Record<string, unknown>;
    const differing = Object.keys(GOLDEN.behaviors).filter((name) => {
        return JSON.stringify(now[name]) !== JSON.stringify(GOLDEN.behaviors[name]);
    });
    expect(differing).toEqual([]);
    expect(Object.keys(now).sort()).toEqual(Object.keys(GOLDEN.behaviors).sort());
}, 60_000);
