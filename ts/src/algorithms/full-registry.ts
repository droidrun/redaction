/**
 * full-registry — the rule kinds of the full tier (`full` in rules.json): the kinds only it uses and the
 * standard kind `regex`. Kept apart from `registry.ts` so that `./sync` loads no full-tier algorithm.
 */
import { prepareCredentialUri } from './credential-uri.js';
import { prepareDashChain } from './dash-chain.js';
import { preparePemKey } from './pem-key.js';
import { prepareRegexRule } from './regex-rule.js';
import { type KindTable } from './registry.js';
import { prepareSendgrid } from './sendgrid.js';
import { prepareToken } from './token.js';

export const FULL_KINDS: KindTable = {
    regex: prepareRegexRule,
    token: prepareToken,
    'dash-chain': prepareDashChain,
    'sendgrid-key': prepareSendgrid,
    'pem-key': preparePemKey,
    'credential-uri': prepareCredentialUri,
};
