/** The corpus file format shared by the generator, the recorder and the replay tests. */
export type CaseOpts = {
    maxChars?: number;
    maxDepth?: number;
    maxNodes?: number;
    skipKeys?: string[];
};

/** A large string written as `[unit, times]` parts, expanded on load. */
export type GenSpec = { parts: Array<[unit: string, times: number]> };

export type CorpusCase = {
    id: string;
    family: string;
    input?: unknown;
    gen?: GenSpec;
    opts?: CaseOpts;
};

export type Digest = { digest: string; length: number };
export type RecordedHit = [ruleId: string, start: number, end: number];
export type Outcome = { out: unknown | Digest; hits: RecordedHit[] };
export type RecordedCase = CorpusCase & { sync: Outcome; async: Outcome };

export type GoldenFile = {
    description: string;
    sourceCommit: string;
    seed: number;
    count: number;
    cases: RecordedCase[];
};

export function expandGen(gen: GenSpec): string {
    return gen.parts.map(([unit, times]) => unit.repeat(times)).join('');
}

export function caseInput(item: CorpusCase): unknown {
    return item.gen === undefined ? item.input : expandGen(item.gen);
}
