/**
 * sync-rules.ts — the deterministic, regex-only rule set, and the ONE rule
 * source of both entry points (the async path adds the full-tier rules of
 * `full-rules.ts` on top). The rules, their order and their parameters are the spec's
 * (`spec/rules.json`: `pipeline`, edited by `strict` in strict mode, then `pii` when asked for); this
 * module only runs them: each rule kind maps to one interpreter under `algorithms/`.
 *
 * Every rule is linear-time or bounded per candidate. Only ranges leave this
 * module; it never logs or returns matched text.
 */
import { collectHits, prepareRules, type PreparedRule } from './algorithms/registry.js';
import { dedupeRanges, type Hit } from './hits.js';
import type { RedactMode } from './mode.js';
import { ALGORITHMS_SPEC, RULES_SPEC, strictRules } from './spec.js';

/** What decides the rule list of a scan: the failure mode and the opt-in `pii` group. */
export type DetectOpts = { mode?: RedactMode; pii?: boolean };

/** Below this length `compat` without `pii` scans nothing (v0.2.0); `strict` and `pii` scan every text. */
const COMPAT_MIN_LENGTH = ALGORITHMS_SPEC.text.minScanLength;

/** The shortest text (or object key) a scan looks at (SPEC 9.1). */
export function scanFloor(opts: DetectOpts): number {
    return opts.mode === 'strict' || opts.pii === true ? 0 : COMPAT_MIN_LENGTH;
}

const PII = prepareRules(RULES_SPEC.pii);
const COMPAT = prepareRules(RULES_SPEC.pipeline);
const STRICT = prepareRules(strictRules(RULES_SPEC.pipeline));
const RULE_LISTS: Record<RedactMode, { plain: PreparedRule[]; withPii: PreparedRule[] }> = {
    compat: { plain: COMPAT, withPii: [...COMPAT, ...PII] },
    strict: { plain: STRICT, withPii: [...STRICT, ...PII] },
};

/** Every secret range the deterministic rules find in `text`, overlapping
 *  ranges merged. Earlier rules win equal starts (the merged hit keeps the first
 *  rule's id). */
export function detectSyncHits(text: string, opts: DetectOpts = {}): Hit[] {
    if (text.length < scanFloor(opts)) return [];
    const lists = RULE_LISTS[opts.mode ?? 'compat'];
    return dedupeRanges(collectHits(opts.pii === true ? lists.withPii : lists.plain, text));
}
