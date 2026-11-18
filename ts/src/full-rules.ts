/**
 * full-rules — the full-tier rules of the spec (`full` in rules.json, the ported secretlint preset),
 * which the async entry runs in addition to the standard rules of `sync-rules.ts`. Only ranges leave this
 * module. The hits come back ordered by start, then end (rule order breaks ties), the order the standard
 * rules are merged after.
 */
import { FULL_KINDS } from './algorithms/full-registry.js';
import { prepareRules } from './algorithms/registry.js';
import type { Hit } from './hits.js';
import { RULES_SPEC } from './spec.js';

const FULL = prepareRules(RULES_SPEC.full, FULL_KINDS);

export function detectFullHits(text: string): Hit[] {
    const hits: Hit[] = [];
    for (const { ruleId, scan } of FULL) {
        for (const range of scan(text)) hits.push({ ruleId, range });
    }
    return hits.sort((a, b) => a.range[0] - b.range[0] || a.range[1] - b.range[1]);
}
