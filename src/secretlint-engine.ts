/**
 * secretlint-engine.ts — the fixed secretlint rule set for `engine.ts`.
 * Everything length-guard/fail-open/flag-gate related lives one
 * layer up in `redact-text.ts`; this module is purely "given text, which
 * rules fire and where".
 *
 * Own rule list rather than `@secretlint/secretlint-rule-preset-recommend`
 * wholesale, for two reasons (both spike-verified against
 * `@secretlint/core@13.0.4`, see redaction-plan.md):
 *
 *   1. The recommend preset includes `secretlint-rule-filter-comments`,
 *      which suppresses ANY finding on a line containing a
 *      `// secretlint-disable`-style comment — a message that happens to
 *      contain that string (accidentally, or a user pasting a config file)
 *      would silently defeat detection for the rest of that content. We
 *      pull every scanner rule from the preset EXCEPT this one.
 *   2. `@secretlint/secretlint-rule-aws`'s `enableIDScanRule` option
 *      defaults to `false` — the bundled preset entry uses that default, so
 *      AWS Access Key IDs / Account IDs (the `AKIA...` shape) are NOT
 *      flagged unless explicitly turned on. We reuse the SAME rule-creator
 *      object the preset already bundles (no separate
 *      `@secretlint/secretlint-rule-aws` dependency needed) with
 *      `enableIDScanRule: true`. The 40-char `AWS_SECRET_ACCESS_KEY=...`
 *      pattern fires either way — it isn't gated by this option.
 *
 * Engine/rule list built ONCE at module load (not per call) — the runner
 * itself is stateless per invocation, so there's nothing to warm up beyond
 * this array construction, but re-deriving it on every scan would still be
 * wasted work on the hot path (backfill loops over hundreds of rows).
 */
import { creator as presetRecommend } from '@secretlint/secretlint-rule-preset-recommend';
import type { SecretLintCoreConfigRule } from '@secretlint/types';
import { jwtRule } from './rules/jwt-rule.js';
import { genericKeywordRule } from './rules/generic-keyword-rule.js';
import { gcpApiKeyRule } from './rules/gcp-api-key-rule.js';
import { xaiApiKeyRule } from './rules/xai-api-key-rule.js';

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

