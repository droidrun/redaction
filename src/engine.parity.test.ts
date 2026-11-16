import { describe, expect, test } from 'bun:test';
import { lintSource } from '@secretlint/core';
import { creator as presetRecommend } from '@secretlint/secretlint-rule-preset-recommend';
import { scanText } from './engine.js';
import { RULES } from './rules/index.js';
import { jwtRule } from './rules/jwt-rule.js';
import { genericKeywordRule } from './rules/generic-keyword-rule.js';
import { gcpApiKeyRule } from './rules/gcp-api-key-rule.js';
import { xaiApiKeyRule } from './rules/xai-api-key-rule.js';

// Independent copy of the original service configuration, not the runner's
// RULES: an accidental omission or changed option must fail parity.
const rules = [
    ...presetRecommend.rules
        .filter((rule) => rule.meta.id !== '@secretlint/secretlint-rule-filter-comments')
        .map((rule) => ({
            id: rule.meta.id,
            rule,
            options: rule.meta.id === '@secretlint/secretlint-rule-aws' ? { enableIDScanRule: true } : {},
        })),
    ...[jwtRule, genericKeywordRule, gcpApiKeyRule, xaiApiKeyRule]
        .map((rule) => ({ id: rule.meta.id, rule, options: {} })),
];

// This fake PEM has only a magic prefix and repeated base64 characters.
// It matches the scanner's shape without containing a usable private key.
const pem = `-----BEGIN PRIVATE KEY-----
MIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----`;
const awsSecret = 'wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY9xxx1';
const fake1Password = 'ops_eyJmYWtlIjoibm90LWEtcmVhbC1jcmVkZW50aWFsIiwicGFkZGluZyI6IkFBQUFBQUFBQUFBQUFB' +
    'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ==';

type PositiveCase = [label: string, input: string, expectedRuleIds: string[], rangeOffset?: number];
const positives: PositiveCase[] = [
    ['AWS ID', 'creds: AKIAQR7ZKT4MW2PLX9BD', ['@secretlint/secretlint-rule-aws']],
    ['AWS secret and overlapping rules', `AWS_SECRET_ACCESS_KEY=${awsSecret}`, [
        '@secretlint/secretlint-rule-aws', 'mobilerun-redaction/generic-keyword',
    ]],
    ['OpenAI', `key is sk-${'a'.repeat(20)}T3BlbkFJ${'b'.repeat(20)}`, [
        '@secretlint/secretlint-rule-openai',
    ]],
    ['GitHub', 'my github token is ghp_16C7e42F292c6912E7710c838347Ae178B4a', [
        '@secretlint/secretlint-rule-github',
    ]],
    ['bare GitHub', 'ghp_16C7e42F292c6912E7710c838347Ae178B4a', ['@secretlint/secretlint-rule-github']],
    ['JWT', 'bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        'eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c', [
        'mobilerun-redaction/jwt',
    ]],
    ['password', 'login: admin password: S0mmer2026!xTr0ub4dor', ['mobilerun-redaction/generic-keyword']],
    ['bare password', 'password: S0mmer2026!xTr0ub4dor', ['mobilerun-redaction/generic-keyword']],
    ['snake case', 'session_token: aB3xK9mQ2pL7wZ4v', ['mobilerun-redaction/generic-keyword']],
    ['camel case', 'clientSecret=Zx9mK2pL7wQ4vB3xA1c', ['mobilerun-redaction/generic-keyword']],
    ['database', 'postgres://admin:hunter2secret@db.example.com:5432/app', [
        '@secretlint/secretlint-rule-database-connection-string',
    ]],
    ['Google', 'GOOGLE_API_KEY=AIza3EiODjfjghFw2GS6-hZByGzeM386y6zvl5f', [
        'mobilerun-redaction/generic-keyword', 'mobilerun-redaction/gcp-api-key',
    ]],
    ['xAI', 'XAI_API_KEY=xai-Y7a1R_QjyDLgpFegN9uQL6yMqjhAl9bXEqgWZtj2dXWHMsj5y' +
        'skfHYLRe61tKKO_PW8NctSUR7m88X6R', [
        'mobilerun-redaction/generic-keyword', 'mobilerun-redaction/xai-api-key',
    ]],
    ['Google trailing hyphen', 'the deploy log mentions AIzaE3ZVSHDBs43BRT3PrSvZ0KshZJRhDBmCji- in passing', [
        'mobilerun-redaction/gcp-api-key',
    ]],
    ['comment bypass', '// secretlint-disable\npassword: S0mmer2026!xTr0ub4dor', [
        'mobilerun-redaction/generic-keyword',
    ]],
    ['independent hits', 'first: ghp_16C7e42F292c6912E7710c838347Ae178B4a then password: ' +
        'S0mmer2026!xTr0ub4dor', [
        '@secretlint/secretlint-rule-github', 'mobilerun-redaction/generic-keyword',
    ]],
    ['short secret', 'pwd=Ab1!Ab1!', ['mobilerun-redaction/generic-keyword']],
    // Exactly one full-size input: the match ends at the 100,000-character boundary.
    ['100k boundary', 'w'.repeat(99_960) + ' apiKey=Vr8tGq3mXpL6bWc9zNe2sYh5fKd1uAoI', [
        'mobilerun-redaction/generic-keyword',
    ]],
    // Deliberate deviation: our BOM ranges refer to the original input; core strips its BOM.
    ['BOM', '\ufeffpassword: S0mmer2026!xTr0ub4dor', ['mobilerun-redaction/generic-keyword'], 1],
    ['Slack', 'xoxb-111111111111-222222222222-fakefixture', ['@secretlint/secretlint-rule-slack']],
    ['npm', `npm_${'A'.repeat(36)}`, ['@secretlint/secretlint-rule-npm']],
    ['Anthropic', `sk-ant-api03-${'A'.repeat(93)}AA`, ['@secretlint/secretlint-rule-anthropic']],
    ['Stripe', 'sk_test_000000000000000000000000', ['@secretlint/secretlint-rule-stripe']],
    ['1Password', fake1Password, ['@secretlint/secretlint-rule-1password']],
    ['fake PEM', pem, ['@secretlint/secretlint-rule-privatekey']],
];

const negatives: [string, string][] = [
    ['bare UUID', 'device 3fa85f64-5717-4562-b3fc-2c963f66afa6 went offline'],
    ['bare SHA-1', 'commit a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 fixed it'],
    ['undefined placeholder', 'default config has token: undefined and that is fine'],
    ['snake-case placeholder', 'set api_key: your_api_key_here in the .env file'],
    ['uppercase placeholder', 'export TOKEN=REPLACE_ME_TOKEN'],
    ['angle-bracket placeholder', 'Authorization: <your-token-here>'],
    ['Google short body', 'legacyId=AIzaS_f0sYnC4Rce_xcEmtOikZcYypDAJ7fS00'],
    ['Google wrong prefix', 'reference=Bxyz3EiODjfjghFw2GS6hZByGzeM386y6zvl5'],
    ['Google oversized body', 'ref=AIzaX5wFmAbkO85TbATCmZwkKljQY9LVKxmYSf7e end'],
    ['xAI prefix decoy', 'the xai-labs team renamed the xai-eval-harness repo'],
    ['xAI short body',
        'legacyRef=xai-ggCKZlvpearv6UguL2RM2ZLr0URcIqRjiVLGbVOIhBNHOYWiqldtDgVoe5q6B06GuCP9V0WBedjuS7c'],
    ['already redacted', 'password: [REDACTED:generic-keyword:4dor]'],
];

describe('runner parity against the original core configuration', () => {
    test.each(positives)('%s', async (_label, content, expectedRuleIds, rangeOffset = 0) => {
        const expected = await lintSource({
            source: { filePath: 'message.txt', content, ext: '.txt', contentType: 'text' },
            options: { config: { rules } },
        });
        const actual = await scanText(content);
        expect(actual.map(({ ruleId }) => ruleId)).toEqual(expectedRuleIds);
        expect(actual).toEqual(expected.messages.map(({ ruleId, range }) => ({
            ruleId, range: [range[0] + rangeOffset, range[1] + rangeOffset],
        })));
    });

    test.each(negatives)('%s', async (_label, content) => {
        const expected = await lintSource({
            source: { filePath: 'message.txt', content, ext: '.txt', contentType: 'text' },
            options: { config: { rules } },
        });
        const actual = await scanText(content);
        expect(actual).toEqual([]);
        expect(actual).toEqual(expected.messages.map(({ ruleId, range }) => ({ ruleId, range })));
    });
});

describe('pinned runtime rule shape', () => {
    test.each(RULES.map(({ id, rule }) => [id, rule] as const))('%s is a scanner', (_id, rule) => {
        expect(rule.meta.type).toBe('scanner');
    });

    const messages = RULES.flatMap(({ id, rule }) => Object.entries(rule.messages)
        .map(([messageId, message]) => [id, messageId, message] as const));
    test.each(messages)('%s/%s has an English message function', (_id, _messageId, message) => {
        expect(typeof message).toBe('object');
        expect(message).toEqual(expect.objectContaining({ en: expect.any(Function) }));
    });
});
