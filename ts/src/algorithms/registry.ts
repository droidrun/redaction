/**
 * registry — which interpreter runs which rule kind of the standard tier (`pipeline`). An unknown kind stops
 * the package at load time. The kinds only the full tier uses are in `full-registry.ts`, so the `./sync` entry,
 * which imports this file, loads none of their code.
 */
import type { Hit } from '../hits.js';
import type { Rule } from '../spec.js';
import { prepareAuthValues } from './auth-values.js';
import { prepareDottedToken } from './dotted-token.js';
import { prepareKeyPairs, prepareKeywordPairs, prepareQuotedPairs, prepareUnquotedPairs } from './pairs.js';
import { preparePemBlocks } from './pem-blocks.js';
import { prepareQueryValues } from './query-values.js';
import { prepareCookieLines, prepareRegexRule, type Scanner } from './regex-rule.js';

export type KindTable = Record<string, (rule: never) => Scanner>;

export const STANDARD_KINDS: KindTable = {
    regex: prepareRegexRule,
    'dotted-token': prepareDottedToken,
    'pem-blocks': preparePemBlocks,
    'cookie-lines': prepareCookieLines,
    'auth-values': prepareAuthValues,
    'keyword-pairs': prepareKeywordPairs,
    'quoted-pairs': prepareQuotedPairs,
    'unquoted-pairs': prepareUnquotedPairs,
    'key-pairs': prepareKeyPairs,
    'query-values': prepareQueryValues,
};

export type PreparedRule = { ruleId: string; scan: Scanner };

/** Every rule of the list over the text, in order, each range tagged with its rule id. */
export function collectHits(rules: readonly PreparedRule[], text: string): Hit[] {
    const hits: Hit[] = [];
    for (const { ruleId, scan } of rules) {
        for (const range of scan(text)) hits.push({ ruleId, range });
    }
    return hits;
}

export function prepareRules(rules: readonly Rule[], kinds: KindTable = STANDARD_KINDS): PreparedRule[] {
    return rules.map((rule) => {
        const prepare = kinds[rule.kind];
        if (prepare === undefined) throw new Error('unknown rule kind in the spec');
        return { ruleId: rule.id, scan: prepare(rule as never) };
    });
}
