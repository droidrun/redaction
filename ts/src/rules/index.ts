/**
 * The fixed rule list `engine.ts` runs; built once at module load. Only the
 * upstream secretlint scanners: the JWT, Google, xAI and keyword rules are the
 * sync rules (`../sync-rules.ts`), which the async path runs as well.
 *
 * Left out and configured here (not in the spec, which does not describe the upstream scanners):
 * filter-comments is excluded so `secretlint-disable` comments in supplied
 * content cannot suppress detection, and AWS ID scanning is enabled because the
 * preset default leaves Access Key IDs and Account IDs unreported.
 */
import { creator as presetRecommend } from '@secretlint/secretlint-rule-preset-recommend';
import type { SecretLintCoreConfigRule } from '@secretlint/types';

// Engine configuration of the upstream scanners (TypeScript only, SPEC section 13): the pinned preset is
// 13.0.4 (package.json); these two settings decide which rules run.
const EXCLUDED_RULES = ['@secretlint/secretlint-rule-filter-comments'];
const RULE_OPTIONS: Record<string, Record<string, unknown>> = {
    '@secretlint/secretlint-rule-aws': { enableIDScanRule: true },
};

function buildRules(): SecretLintCoreConfigRule[] {
    const upstream: SecretLintCoreConfigRule[] = presetRecommend.rules
        .filter((rule) => !EXCLUDED_RULES.includes(rule.meta.id))
        .map((rule) => ({ id: rule.meta.id, rule, options: RULE_OPTIONS[rule.meta.id] ?? {} }));
    return upstream;
}

export const RULES = buildRules();

