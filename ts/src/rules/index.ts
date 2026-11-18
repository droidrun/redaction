/**
 * The fixed rule list `engine.ts` runs; built once at module load. Only the
 * upstream secretlint scanners: the JWT, Google, xAI and keyword rules are the
 * sync rules (`../sync-rules.ts`), which the async path runs as well.
 *
 * The spec (`upstream`) decides which rules are left out and their options:
 * filter-comments is excluded so `secretlint-disable` comments in supplied
 * content cannot suppress detection, and AWS ID scanning is enabled because the
 * preset default leaves Access Key IDs and Account IDs unreported.
 */
import { creator as presetRecommend } from '@secretlint/secretlint-rule-preset-recommend';
import type { SecretLintCoreConfigRule } from '@secretlint/types';
import { ALGORITHMS_SPEC } from '../spec.js';

const { excludeRules, ruleOptions } = ALGORITHMS_SPEC.upstream;

function buildRules(): SecretLintCoreConfigRule[] {
    const upstream: SecretLintCoreConfigRule[] = presetRecommend.rules
        .filter((rule) => !excludeRules.includes(rule.meta.id))
        .map((rule) => ({ id: rule.meta.id, rule, options: ruleOptions[rule.meta.id] ?? {} }));
    return upstream;
}

export const RULES = buildRules();

