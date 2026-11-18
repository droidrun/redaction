/** The deterministic golden corpus: the same seed gives the same inputs, byte for byte. */
import {
    astralFamilies, boundaryFamilies, capFamilies, fuzzFamilies, jsonShapeFamilies, largeFamilies,
    prefixFamilies, separatorFamilies,
} from './families.ts';
import { mulberry32 } from './rng.ts';
import type { CaseOpts, CorpusCase, GenSpec } from './types.ts';

export const CORPUS_SEED = 0x6977143;

export function generateCorpus(vectorInputs: readonly unknown[]): CorpusCase[] {
    const rng = mulberry32(CORPUS_SEED);
    const cases: CorpusCase[] = [];
    const counters = new Map<string, number>();
    const nextId = (family: string): string => {
        const n = counters.get(family) ?? 0;
        counters.set(family, n + 1);
        return `${family}-${n}`;
    };
    const add = (family: string, input: unknown, opts?: CaseOpts): void => {
        cases.push({ id: nextId(family), family, input, ...(opts ? { opts } : {}) });
    };
    const addGen = (family: string, gen: GenSpec, opts?: CaseOpts): void => {
        cases.push({ id: nextId(family), family, gen, ...(opts ? { opts } : {}) });
    };
    const sinks = { add, addGen };
    for (const input of vectorInputs) add('vector', input);
    prefixFamilies(sinks);
    separatorFamilies(sinks, rng);
    astralFamilies(sinks, rng);
    jsonShapeFamilies(sinks, rng);
    capFamilies(sinks, rng);
    boundaryFamilies(sinks, rng);
    fuzzFamilies(sinks, rng);
    largeFamilies(sinks);
    return cases;
}
