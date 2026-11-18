/**
 * Replay of one corpus case through a package entry point: shared by the recorder
 * (`record.ts`, run against the unchanged package) and the golden test (run against the
 * current code), so both build outputs and hits the same way.
 */
import { createHash } from 'node:crypto';
import { caseInput, type CorpusCase, type Digest, type Outcome, type RecordedHit } from './types.ts';

export type HitLike = { ruleId: string; range: readonly [number, number] };

export type Entry = {
    redactTextSync: (text: string, opts?: object) => { text: string; hits: HitLike[] };
    redactJsonValueSync: (value: unknown, opts?: object) => unknown;
    redactText: (text: string) => Promise<{ text: string; hits: HitLike[] }>;
    redactJsonValue: (value: unknown, stats: { hits: HitLike[] }, opts?: object) => Promise<unknown>;
};

/** Outputs longer than this (in JSON) are stored as a digest. */
const DIGEST_ABOVE = 20_000;

export function toHits(hits: readonly HitLike[]): RecordedHit[] {
    return hits.map((hit) => [hit.ruleId, hit.range[0], hit.range[1]]);
}

export function summarize(out: unknown): unknown | Digest {
    const serialized = JSON.stringify(out) ?? 'undefined';
    if (serialized.length <= DIGEST_ABOVE) return out;
    return { digest: createHash('sha256').update(serialized).digest('hex'), length: serialized.length };
}

async function replayText(entry: Entry, input: string, item: CorpusCase) {
    const sync = entry.redactTextSync(input, { maxChars: item.opts?.maxChars });
    const full = await entry.redactText(input);
    return {
        sync: { out: summarize(sync.text), hits: toHits(sync.hits) },
        async: { out: summarize(full.text), hits: toHits(full.hits) },
    };
}

async function replayJson(entry: Entry, input: unknown, item: CorpusCase) {
    const opts = item.opts ?? {};
    const skip = opts.skipKeys === undefined ? {} : { skipKeys: new Set(opts.skipKeys) };
    const syncStats = { hits: [] as HitLike[] };
    const syncOut = entry.redactJsonValueSync(input, {
        maxChars: opts.maxChars,
        maxDepth: opts.maxDepth,
        maxNodes: opts.maxNodes,
        ...skip,
        stats: syncStats,
    });
    const asyncStats = { hits: [] as HitLike[] };
    const asyncOut = await entry.redactJsonValue(input, asyncStats, skip);
    return {
        sync: { out: summarize(syncOut), hits: toHits(syncStats.hits) },
        async: { out: summarize(asyncOut), hits: toHits(asyncStats.hits) },
    };
}

export async function replayCase(entry: Entry, item: CorpusCase): Promise<{ sync: Outcome; async: Outcome }> {
    const input = caseInput(item);
    if (typeof input === 'string') return replayText(entry, input, item);
    return replayJson(entry, input, item);
}
