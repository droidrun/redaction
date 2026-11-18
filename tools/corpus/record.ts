/**
 * Record the corpus through a package entry point.
 *   bun tools/corpus/record.ts <entry.ts> <out.json> [sourceCommit]
 * Run against the unchanged package at 6977143 it writes the golden file; the golden
 * replay test compares the current code with that file.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { CORPUS_SEED, generateCorpus } from './generate.ts';
import {
    caseInput,
    type CorpusCase,
    type Digest,
    type GoldenFile,
    type Outcome,
    type RecordedCase,
    type RecordedHit,
} from './types.ts';

type Entry = {
    redactTextSync: (text: string, opts?: object) => { text: string; hits: HitLike[] };
    redactJsonValueSync: (value: unknown, opts?: object) => unknown;
    redactText: (text: string) => Promise<{ text: string; hits: HitLike[] }>;
    redactJsonValue: (value: unknown, stats: { hits: HitLike[] }, opts?: object) => Promise<unknown>;
};
type HitLike = { ruleId: string; range: readonly [number, number] };

const DIGEST_ABOVE = 20_000;

type VectorCase = { input?: unknown; mode?: string; opts?: object; inputGen?: object };

export function vectorInputs(vectorsDir: string): unknown[] {
    const files = readdirSync(vectorsDir)
        .filter((name) => name.endsWith('.json'))
        .sort();
    return files.flatMap((name) => {
        const text = readFileSync(join(vectorsDir, name), 'utf8');
        const parsed = JSON.parse(text) as { cases: VectorCase[] };
        // Cases that set a mode, limits or a generated input are not plain inputs of the corpus.
        const plain = parsed.cases.filter((item) => {
            return item.mode === undefined && item.opts === undefined && item.inputGen === undefined;
        });
        return plain.map((item) => item.input);
    });
}

function toHits(hits: readonly HitLike[]): RecordedHit[] {
    return hits.map((hit) => [hit.ruleId, hit.range[0], hit.range[1]]);
}

export function summarize(out: unknown): unknown | Digest {
    const serialized = JSON.stringify(out) ?? 'undefined';
    if (serialized.length <= DIGEST_ABOVE) return out;
    return { digest: createHash('sha256').update(serialized).digest('hex'), length: serialized.length };
}

async function recordOne(entry: Entry, item: CorpusCase): Promise<RecordedCase> {
    const input = caseInput(item);
    const opts = item.opts ?? {};
    const syncOpts = { maxChars: opts.maxChars, maxDepth: opts.maxDepth, maxNodes: opts.maxNodes };
    const skip = opts.skipKeys === undefined ? {} : { skipKeys: new Set(opts.skipKeys) };
    let sync: Outcome;
    let asyncOutcome: Outcome;
    if (typeof input === 'string') {
        const s = entry.redactTextSync(input, { maxChars: opts.maxChars });
        sync = { out: summarize(s.text), hits: toHits(s.hits) };
        const a = await entry.redactText(input);
        asyncOutcome = { out: summarize(a.text), hits: toHits(a.hits) };
    } else {
        const syncStats = { hits: [] as HitLike[] };
        const so = entry.redactJsonValueSync(input, { ...syncOpts, ...skip, stats: syncStats });
        sync = { out: summarize(so), hits: toHits(syncStats.hits) };
        const asyncStats = { hits: [] as HitLike[] };
        const ao = await entry.redactJsonValue(input, asyncStats, skip);
        asyncOutcome = { out: summarize(ao), hits: toHits(asyncStats.hits) };
    }
    return { ...item, sync, async: asyncOutcome };
}

export async function recordCorpus(entry: Entry, inputs: readonly unknown[]): Promise<RecordedCase[]> {
    const recorded: RecordedCase[] = [];
    for (const item of generateCorpus(inputs)) recorded.push(await recordOne(entry, item));
    return recorded;
}

async function main(): Promise<void> {
    const [entryPath, outPath, commit = 'unknown'] = process.argv.slice(2);
    if (!entryPath || !outPath) throw new Error('usage: record.ts <entry.ts> <out.json> [sourceCommit]');
    const entry = (await import(resolve(entryPath))) as Entry;
    const repoRoot = resolve(import.meta.dir, '..', '..');
    const cases = await recordCorpus(entry, vectorInputs(join(repoRoot, process.argv[5] ?? 'vectors')));
    const file: GoldenFile = {
        description: 'Outputs of the package at the source commit for the seeded corpus (tools/corpus).',
        sourceCommit: commit,
        seed: CORPUS_SEED,
        count: cases.length,
        cases,
    };
    writeFileSync(outPath, JSON.stringify(file));
    console.log(`recorded ${cases.length} cases`);
}

if (import.meta.main) await main();
