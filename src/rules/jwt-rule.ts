/**
 * jwt-rule.ts — custom secretlint rule: JSON Web Tokens.
 *
 * Not covered by `@secretlint/secretlint-rule-preset-recommend` (verified via
 * the spike — see redaction-plan.md). Three base64url segments joined by
 * dots; the header segment is required to start with `eyJ` (base64 of
 * `{"` — true for every standard JWT header, since it always opens with
 * `{"alg":...}` or `{"typ":...}`) to keep false positives near zero on
 * ordinary dotted identifiers. Bounded quantifiers only (no nested
 * repetition) — safe against ReDoS on adversarial input.
 */
import type { SecretLintRuleCreator } from '@secretlint/types';

const JWT_PATTERN = /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/g;

const MESSAGES = {
    JWT: {
        en: () => 'found a JSON Web Token',
    },
};

export const jwtRule: SecretLintRuleCreator = {
    messages: MESSAGES,
    meta: {
        id: 'mobilerun-redaction/jwt',
        type: 'scanner',
        recommended: true,
        supportedContentTypes: ['text'],
    },
    create(context) {
        const t = context.createTranslator(MESSAGES);
        return {
            file(source) {
                for (const match of source.content.matchAll(JWT_PATTERN)) {
                    const index = match.index ?? 0;
                    const text = match[0];
                    context.report({
                        message: t('JWT'),
                        range: [index, index + text.length],
                    });
                }
            },
        };
    },
};
