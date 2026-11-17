/**
 * generic-keyword-rule.ts — custom secretlint rule: `label: value` /
 * `label=value` pairs where the label looks like a credential and the value
 * has "evidence" of actually being secret material (not `password: undefined`
 * or a doc example).
 *
 * Only the VALUE is reported/redacted — the label stays untouched. The
 * pattern and the evidence test live in `../patterns.ts`, shared with the
 * sync path (one rule source).
 */
import type { SecretLintRuleCreator } from '@secretlint/types';
import { keywordValueRanges } from '../patterns.js';

const MESSAGES = {
    KEYWORD_VALUE: {
        en: () => 'found a credential-looking key/value pair',
    },
};

export const genericKeywordRule: SecretLintRuleCreator = {
    messages: MESSAGES,
    meta: {
        id: 'mobilerun-redaction/generic-keyword',
        type: 'scanner',
        recommended: true,
        supportedContentTypes: ['text'],
    },
    create(context) {
        const t = context.createTranslator(MESSAGES);
        return {
            file(source) {
                for (const range of keywordValueRanges(source.content)) {
                    context.report({ message: t('KEYWORD_VALUE'), range });
                }
            },
        };
    },
};
