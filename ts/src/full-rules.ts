/**
 * full-rules — the full-tier rules of the spec (`full` in rules.json, the ported secretlint preset),
 * which the async entry runs in addition to the standard rules of `sync-rules.ts`. Only ranges leave this
 * module. The hits come back ordered by start, then end (rule order breaks ties), the order the standard
 * rules are merged after.
 */
import { FULL_KINDS } from './algorithms/full-registry.js';
import { collectHits, prepareRules } from './algorithms/registry.js';
import { dedupeRanges, type Hit } from './hits.js';
import { registerFullKeyDetector } from './key-detectors.js';
import { ALGORITHMS_SPEC, RULES_SPEC } from './spec.js';
import { detectSyncHits, type DetectOpts } from './sync-rules.js';

const FULL = prepareRules(RULES_SPEC.full, FULL_KINDS);

export function detectFullHits(text: string): Hit[] {
    return collectHits(FULL, text).sort((a, b) => a.range[0] - b.range[0] || a.range[1] - b.range[1]);
}

/** TypeScript extension (SPEC 13): the hits of the full tier carry the 0.2.0 id of the secretlint rule they
 *  were ported from, so consumers that read `hits` see no change; the placeholder shortens it. */
const LEGACY_RULE_ID_PREFIX = ALGORITHMS_SPEC.placeholder.stripPrefixes[0] as string;

export function withLegacyId(hit: Hit): Hit {
    return { ruleId: `${LEGACY_RULE_ID_PREFIX}${hit.ruleId}`, range: hit.range };
}

/** The merged hits of the full tier over one short text (an object key, SPEC 9.4): the full-tier rules, then
 *  the standard rules, no windows (a key is at most `sync.maxKeyChars` long). */
export function detectFullTierKeyHits(key: string, opts: DetectOpts = {}): Hit[] {
    return dedupeRanges([...detectFullHits(key).map(withLegacyId), ...detectSyncHits(key, opts)]);
}

registerFullKeyDetector(detectFullTierKeyHits);
