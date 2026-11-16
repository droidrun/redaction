/**
 * The fixed rule list `engine.ts` runs; built once at module load.
 *
 * 1. Exclude filter-comments so `secretlint-disable` comments in supplied
 *    content cannot suppress detection.
 * 2. Enable AWS ID scanning because the preset default leaves Access Key
 *    IDs and Account IDs unreported. Secret Access Key scanning is always on.
 */
import { creator as presetRecommend } from '@secretlint/secretlint-rule-preset-recommend';
import type { SecretLintCoreConfigRule } from '@secretlint/types';
import { jwtRule } from './jwt-rule.js';
import { genericKeywordRule } from './generic-keyword-rule.js';
import { gcpApiKeyRule } from './gcp-api-key-rule.js';
import { xaiApiKeyRule } from './xai-api-key-rule.js';

const FILTER_COMMENTS_RULE_ID = '@secretlint/secretlint-rule-filter-comments';
const AWS_RULE_ID = '@secretlint/secretlint-rule-aws';

function buildRules(): SecretLintCoreConfigRule[] {
    const upstream: SecretLintCoreConfigRule[] = presetRecommend.rules
        .filter((rule) => rule.meta.id !== FILTER_COMMENTS_RULE_ID)
        .map((rule) => ({
            id: rule.meta.id,
            rule,
            options: rule.meta.id === AWS_RULE_ID ? { enableIDScanRule: true } : {},
        }));
    return [
        ...upstream,
        { id: jwtRule.meta.id, rule: jwtRule, options: {} },
        { id: genericKeywordRule.meta.id, rule: genericKeywordRule, options: {} },
        { id: gcpApiKeyRule.meta.id, rule: gcpApiKeyRule, options: {} },
        { id: xaiApiKeyRule.meta.id, rule: xaiApiKeyRule, options: {} },
    ];
}

export const RULES = buildRules();

