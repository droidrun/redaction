/**
 * Record the corpus and the behaviour probes through a package entry point.
 *   bun tools/corpus/record.ts <entry.ts> <out.json.gz> [sourceCommit] [vectorsDir]
 * Run against the unchanged package at b12879a it writes the golden file; the golden
 * replay test compares the current code with that file.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { gzipSync } from 'node:zlib';
import { runBehaviors, type Api } from './behaviors.ts';
import { CORPUS_SEED, generateCorpus } from './generate.ts';
import { replayCase, type Entry } from './replay.ts';
import type { GoldenFile, RecordedCase } from './types.ts';

type VectorCase = { input?: unknown; mode?: string; opts?: object; inputGen?: object };

/** The plain inputs of the vector files (cases that set a mode, limits or a generated input are not). */
export function vectorInputs(vectorsDir: string): unknown[] {
    const files = readdirSync(vectorsDir)
        .filter((name) => name.endsWith('.json'))
        .sort();
    return files.flatMap((name) => {
        const text = readFileSync(join(vectorsDir, name), 'utf8');
        const parsed = JSON.parse(text) as { cases: VectorCase[] };
        const plain = parsed.cases.filter((item) => {
            return item.mode === undefined && item.opts === undefined && item.inputGen === undefined;
        });
        return plain.map((item) => item.input);
    });
}

export async function recordCorpus(entry: Entry, inputs: readonly unknown[]): Promise<RecordedCase[]> {
    const recorded: RecordedCase[] = [];
    for (const item of generateCorpus(inputs)) {
        recorded.push({ ...item, ...(await replayCase(entry, item)) });
    }
    return recorded;
}

async function main(): Promise<void> {
    const [entryPath, outPath, commit = 'unknown', vectorsDir = 'spec/vectors'] = process.argv.slice(2);
    if (!entryPath || !outPath) throw new Error('usage: record.ts <entry.ts> <out.json.gz> [commit] [dir]');
    const module = await import(resolve(entryPath));
    const repoRoot = resolve(import.meta.dir, '..', '..');
    const cases = await recordCorpus(module as Entry, vectorInputs(join(repoRoot, vectorsDir)));
    const file: GoldenFile = {
        description: 'Outputs of the package at the source commit for the seeded corpus (tools/corpus).',
        sourceCommit: commit,
        seed: CORPUS_SEED,
        count: cases.length,
        cases,
        behaviors: await runBehaviors(module as Api),
    };
    writeFileSync(outPath, gzipSync(JSON.stringify(file), { level: 9 }));
    console.log(`recorded ${cases.length} cases and ${Object.keys(file.behaviors).length} probes`);
}

if (import.meta.main) await main();
