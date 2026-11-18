/**
 * golden.test.ts — the rules moved from code into the spec without changing a byte
 * of output: the seeded corpus (`tools/corpus`, 7,800+ inputs: fuzz families, every
 * vector input, NBSP/BOM/U+202F/U+2028 separators, astral characters, lone surrogates,
 * adversarial prefixes before every rule, integer-like keys, key collisions, cases
 * crossing every cap) gives the outputs and hits that commit b12879a recorded in
 * `spec/corpus/golden-b12879a.json`, on all four entry points.
 */
import { expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { redactJsonValue, redactJsonValueSync, redactText, redactTextSync } from './index.js';

type Outcome = { out: unknown; hits: Array<[string, number, number]> };
type GoldenCase = {
    id: string;
    input?: unknown;
    gen?: { parts: Array<[string, number]> };
    opts?: { maxChars?: number; maxDepth?: number; maxNodes?: number; skipKeys?: string[] };
    sync: Outcome;
    async: Outcome;
};

const GOLDEN = JSON.parse(
    readFileSync(join(import.meta.dir, '..', '..', 'spec', 'corpus', 'golden-b12879a.json'), 'utf8'),
) as { count: number; cases: GoldenCase[] };
const DIGEST_ABOVE = 20_000;

function inputOf(item: GoldenCase): unknown {
    return item.gen === undefined
        ? item.input
        : item.gen.parts.map(([unit, times]) => unit.repeat(times)).join('');
}

function summarize(out: unknown): unknown {
    const serialized = JSON.stringify(out) ?? 'undefined';
    if (serialized.length <= DIGEST_ABOVE) return out;
    return { digest: createHash('sha256').update(serialized).digest('hex'), length: serialized.length };
}

const toHits = (hits: Array<{ ruleId: string; range: readonly [number, number] }>): Outcome['hits'] => {
    return hits.map((hit) => [hit.ruleId, hit.range[0], hit.range[1]]);
};

async function replay(item: GoldenCase): Promise<{ sync: Outcome; async: Outcome }> {
    const input = inputOf(item);
    const opts = item.opts ?? {};
    if (typeof input === 'string') {
        const sync = redactTextSync(input, { maxChars: opts.maxChars });
        const full = await redactText(input);
        return {
            sync: { out: summarize(sync.text), hits: toHits(sync.hits) },
            async: { out: summarize(full.text), hits: toHits(full.hits) },
        };
    }
    const skip = opts.skipKeys === undefined ? {} : { skipKeys: new Set(opts.skipKeys) };
    const syncStats = { hits: [] as Array<{ ruleId: string; range: readonly [number, number] }> };
    const syncOut = redactJsonValueSync(input, {
        maxChars: opts.maxChars,
        maxDepth: opts.maxDepth,
        maxNodes: opts.maxNodes,
        ...skip,
        stats: syncStats as { hits: never[] },
    });
    const asyncStats = { hits: [] as Array<{ ruleId: string; range: readonly [number, number] }> };
    const asyncOut = await redactJsonValue(input, asyncStats as { hits: never[] }, skip);
    return {
        sync: { out: summarize(syncOut), hits: toHits(syncStats.hits) },
        async: { out: summarize(asyncOut), hits: toHits(asyncStats.hits) },
    };
}

test('the corpus holds at least 5000 cases', () => {
    expect(GOLDEN.cases.length).toBe(GOLDEN.count);
    expect(GOLDEN.count).toBeGreaterThanOrEqual(5000);
});

test('every corpus case gives the recorded output and hits, sync and async', async () => {
    const differing: string[] = [];
    for (const item of GOLDEN.cases) {
        const now = await replay(item);
        const same =
            JSON.stringify(now.sync) === JSON.stringify(item.sync) &&
            JSON.stringify(now.async) === JSON.stringify(item.async);
        if (!same) differing.push(item.id);
    }
    expect(differing).toEqual([]);
}, 120_000);
