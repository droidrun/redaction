/**
 * registry — which interpreter runs which rule kind of the spec (`pipeline` of the standard tier, `full` of
 * the full tier). An unknown kind stops the package at load time.
 */
import type { Rule } from '../spec.js';
import { prepareAuthValues } from './auth-values.js';
import { prepareCredentialUri } from './credential-uri.js';
import { prepareDashChain } from './dash-chain.js';
import { prepareDottedToken } from './dotted-token.js';
import { prepareKeywordPairs, prepareQuotedPairs, prepareUnquotedPairs } from './pairs.js';
import { preparePemBlocks } from './pem-blocks.js';
import { preparePemKey } from './pem-key.js';
import { prepareQueryValues } from './query-values.js';
import { prepareCookieLines, prepareRegexRule, type Scanner } from './regex-rule.js';
import { prepareSendgrid } from './sendgrid.js';
import { prepareToken } from './token.js';

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
    token: prepareToken,
    'dash-chain': prepareDashChain,
    'sendgrid-key': prepareSendgrid,
    'pem-key': preparePemKey,
    'credential-uri': prepareCredentialUri,
};

export type PreparedRule = { ruleId: string; scan: Scanner };

export function prepareRules(rules: readonly Rule[]): PreparedRule[] {
    return rules.map((rule) => {
        const prepare = PREPARE[rule.kind];
        if (prepare === undefined) throw new Error('unknown rule kind in the spec');
        return { ruleId: rule.id, scan: prepare(rule as never) };
    });
}
