/**
 * xai-api-key-rule.ts — custom secretlint rule: xAI (x.ai / Grok) API keys.
 *
 * No upstream secretlint rule exists for xAI at all (verified via the spike:
 * neither `@secretlint/secretlint-rule-preset-recommend@13.0.4` nor a
 * separate `@secretlint/secretlint-rule-xai` package exists). This rule adds
 * that coverage from scratch.
 *
 * Format researched against TruffleHog's maintained, API-verified detector
 * (`pkg/detectors/xai/xai.go` in trufflesecurity/trufflehog, current as of
 * this writing) rather than guessed: `xai-` followed by EXACTLY 80 chars of
 * `[0-9a-zA-Z_]` — TruffleHog's own pattern is
 * `\b(xai-[0-9a-zA-Z_]{80})\b`, and it round-trips the match against
 * `https://api.x.ai/v1/api-key` to confirm validity, so this is a
 * ground-truth-checked shape, not a documentation guess.
 *
 * Deliberately requires the full 80-char body (not just the `xai-` prefix
 * plus "something long") — an ordinary word or identifier that happens to
 * start with the 4 literal chars `xai-` would have to also carry 80 more
 * alphanumeric/underscore chars immediately after to false-positive, which
 * essentially never happens outside a real key.
 *
 * Bounded quantifier only (`{80}`, no unbounded repetition) — same ReDoS bar
 * as the other custom rules in this directory.
 */
import type { SecretLintRuleCreator } from '@secretlint/types';

const XAI_API_KEY_PATTERN = /\bxai-[0-9a-zA-Z_]{80}\b/g;

const MESSAGES = {
    XAI_API_KEY: {
        en: () => 'found an xAI (x.ai) API key',
    },
};

export const xaiApiKeyRule: SecretLintRuleCreator = {
    messages: MESSAGES,
    meta: {
        id: 'mobilerun-redaction/xai-api-key',
        type: 'scanner',
        recommended: true,
        supportedContentTypes: ['text'],
    },
    create(context) {
        const t = context.createTranslator(MESSAGES);
        return {
            file(source) {
                for (const match of source.content.matchAll(XAI_API_KEY_PATTERN)) {
                    const index = match.index ?? 0;
                    const text = match[0];
                    context.report({
                        message: t('XAI_API_KEY'),
                        range: [index, index + text.length],
                    });
                }
            },
        };
    },
};
