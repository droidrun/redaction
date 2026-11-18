/**
 * The fixed rule list `engine.ts` runs; built once at module load. Only the
 * upstream secretlint scanners: the JWT, Google, xAI and keyword rules are the
 * sync rules (`../sync-rules.ts`), which the async path runs as well.
 *
 * 1. Exclude filter-comments so `secretlint-disable` comments in supplied
 *    content cannot suppress detection.
 * 2. Enable AWS ID scanning because the preset default leaves Access Key
 *    IDs and Account IDs unreported. Secret Access Key scanning is always on.
 */
import { creator as presetRecommend } from '@secretlint/secretlint-rule-preset-recommend';
import type { SecretLintCoreConfigRule } from '@secretlint/types';

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
    return upstream;
}

export const RULES = buildRules();

