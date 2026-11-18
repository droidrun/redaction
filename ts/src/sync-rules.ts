/**
 * sync-rules.ts — the deterministic, regex-only rule set, and the ONE rule
 * source of both entry points (the async path adds the upstream secretlint
 * scanners on top). The rules, their order and their parameters are the spec's
 * (`spec/rules.json` pipeline); this module only runs them: each rule kind maps
 * to one interpreter under `algorithms/`.
 *
 * Every rule is linear-time or bounded per candidate. Only ranges leave this
 * module; it never logs or returns matched text.
 */
import { prepareAuthValues } from './algorithms/auth-values.js';
import { prepareDottedToken } from './algorithms/dotted-token.js';
import { prepareKeywordPairs, prepareQuotedPairs, prepareUnquotedPairs } from './algorithms/pairs.js';
import { preparePemBlocks } from './algorithms/pem-blocks.js';
import { prepareQueryValues } from './algorithms/query-values.js';
import { prepareCookieLines, prepareRegexRule, type Scanner } from './algorithms/regex-rule.js';
import { dedupeRanges, type Hit } from './hits.js';
import { RULES_SPEC, type Rule } from './spec.js';

const PREPARE: Record<string, (rule: never) => Scanner> = {
    regex: prepareRegexRule,
    'dotted-token': prepareDottedToken,
    'pem-blocks': preparePemBlocks,
    'cookie-lines': prepareCookieLines,
    'auth-values': prepareAuthValues,
    'keyword-pairs': prepareKeywordPairs,
    'quoted-pairs': prepareQuotedPairs,
    'unquoted-pairs': prepareUnquotedPairs,
    'query-values': prepareQueryValues,
};

type PreparedRule = { ruleId: string; scan: Scanner };

function prepareRule(rule: Rule): PreparedRule {
    const prepare = PREPARE[rule.kind];
    if (prepare === undefined) throw new Error('unknown rule kind in the spec');
    return { ruleId: rule.id, scan: prepare(rule as never) };
}

const PIPELINE: PreparedRule[] = RULES_SPEC.pipeline.map(prepareRule);

/** Every secret range the deterministic rules find in `text`, overlapping
 *  ranges merged. Earlier rules win equal starts (the merged hit keeps the first
 *  rule's id). */
export function detectSyncHits(text: string): Hit[] {
    const hits: Hit[] = [];
    for (const { ruleId, scan } of PIPELINE) {
        for (const range of scan(text)) hits.push({ ruleId, range });
    }
    return dedupeRanges(hits);
}
