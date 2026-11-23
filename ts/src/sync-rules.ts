/**
 * sync-rules.ts — the deterministic, regex-only rule set, and the ONE rule
 * source of both entry points (the async path adds the full-tier rules of
 * `full-rules.ts` on top). The rules, their order and their parameters are the spec's
 * (`spec/rules.json` pipeline); this module only runs them: each rule kind maps
 * to one interpreter under `algorithms/`.
 *
 * Every rule is linear-time or bounded per candidate. Only ranges leave this
 * module; it never logs or returns matched text.
 */
import { collectHits, prepareRules } from './algorithms/registry.js';
import { dedupeRanges, type Hit } from './hits.js';
import { RULES_SPEC } from './spec.js';

const PIPELINE = prepareRules(RULES_SPEC.pipeline);

/** Every secret range the deterministic rules find in `text`, overlapping
 *  ranges merged. Earlier rules win equal starts (the merged hit keeps the first
 *  rule's id). */
export function detectSyncHits(text: string): Hit[] {
    return dedupeRanges(collectHits(PIPELINE, text));
}
