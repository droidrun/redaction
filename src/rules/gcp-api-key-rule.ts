/**
 * gcp-api-key-rule.ts — custom secretlint rule: Google (GCP) API keys.
 *
 * `@secretlint/secretlint-rule-gcp` (bundled in preset-recommend) ONLY
 * inspects `.p12`/`.json` FILE content for GCP Service Account keys — it has
 * no regex for the `AIza…` API-key STRING shape. This rule detects pasted
 * `AIza…` browser/server API keys.
 *
 * `AIza` followed by exactly 35 chars from the base64url-ish alphabet Google
 * uses for these keys (`[0-9A-Za-z_-]`) — 39 chars total, matching the
 * well-documented, fixed-length Google API key format. Fixed length + fixed
 * prefix keeps false positives near zero: an ordinary identifier or hash
 * would have to coincidentally start with the 4 literal chars `AIza` AND be
 * exactly 39 chars long.
 *
 * Bounded quantifier only (`{35}`, no unbounded repetition) — same ReDoS bar
 * as `jwt-rule.ts` / `generic-keyword-rule.ts`.
 *
 * Boundaries use explicit character-class lookarounds, NOT `\b`. The body
 * charset includes `-`, a non-word char — a real 39-char key whose LAST body
 * char is `-` (~1/64 of keys) sits at a non-word→non-word transition right
 * before a following space/quote/EOS/`=`, so `\b` fails to match there and
 * the fixed `{35}` quantifier can't backtrack to compensate: the whole key
 * silently escapes redaction. `(?<![0-9A-Za-z_-])…(?![0-9A-Za-z_-])` matches
 * on the actual key alphabet instead of word-char-ness, and the trailing
 * lookahead still correctly rejects a 36+-char body run.
 */
import type { SecretLintRuleCreator } from '@secretlint/types';
import { GCP_API_KEY_PATTERN } from '../patterns.js';

const MESSAGES = {
    GCP_API_KEY: {
        en: () => 'found a Google (GCP) API key',
    },
};

export const gcpApiKeyRule: SecretLintRuleCreator = {
    messages: MESSAGES,
    meta: {
        id: 'mobilerun-redaction/gcp-api-key',
        type: 'scanner',
        recommended: true,
        supportedContentTypes: ['text'],
    },
    create(context) {
        const t = context.createTranslator(MESSAGES);
        return {
            file(source) {
                for (const match of source.content.matchAll(GCP_API_KEY_PATTERN)) {
                    const index = match.index ?? 0;
                    const text = match[0];
                    context.report({
                        message: t('GCP_API_KEY'),
                        range: [index, index + text.length],
                    });
                }
            },
        };
    },
};
