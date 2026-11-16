import { describe, expect, test } from 'bun:test';
import { lintSource } from '@secretlint/core';
import { creator as presetRecommend } from '@secretlint/secretlint-rule-preset-recommend';
import { scanText } from './engine.js';
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

// Positive/negative string inputs from the moved text and JSON-value suites,
// including boundary fixtures. Key-context itself belongs to the JSON walker.
const negatives: [string, string][] = [
        ['bare UUID (no credential-keyword label)', 'device 3fa85f64-5717-4562-b3fc-2c963f66afa6 went ' +
            'offline'],
        ['bare SHA-1 hash', 'commit a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 fixed it'],
        ['bare base64 data URI', 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB'],
        ['plain URL', 'see https://example.com/path?query=abcdefgh123 for docs'],
        ['token: undefined', 'default config has token: undefined and that is fine'],
        ['doc placeholder (snake_case)', 'set api_key: your_api_key_here in the .env file'],
        ['doc placeholder (SCREAMING_SNAKE)', 'export TOKEN=REPLACE_ME_TOKEN'],
        ['doc placeholder (angle brackets)', 'Authorization: <your-token-here>'],
        ['trivial value: changeme', 'password: changeme'],
        ['trivial value: xxxxxxxx mask', 'api_key: xxxxxxxxxxxxxxxx'],
        ['trivial value: asterisk mask', 'secret: ****************'],
        ['short design token (below the 8-char floor)', 'spacing_token: 16px, color_token: #fff'],
        // Gap 1/2 false-positive guards: same-shape-but-wrong-length strings
        // must not trip the new fixed-length custom rules.
        [
            'AIza decoy: 34-char body (one short of the real 35) — not a valid Google key shape',
            'legacyId=AIzaS_f0sYnC4Rce_xcEmtOikZcYypDAJ7fS00',
        ],
        [
            'AIza decoy: 39-char random string that does NOT start with the literal AIza prefix',
            'reference=Bxyz3EiODjfjghFw2GS6hZByGzeM386y6zvl5',
        ],
        [
            'xai- decoy: bare "xai-" prefix used as an ordinary identifier fragment, not a key',
            'the xai-labs team renamed the xai-eval-harness repo',
        ],
        [
            'xai- decoy: 79-char body (one short of the real 80) — not a valid xAI key shape',
            'legacyRef=xai-ggCKZlvpearv6UguL2RM2ZLr0URcIqRjiVLGbVOIhBNHOYWiqldtDgVoe5q6B06GuCP9V0WBedjuS7c',
        ],
    ];
const pem = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDfU36d/BY7T9t2
gbzxK15q2zNdjeCxdWZKJXB8o6Nu1Lq2O4bCSotp/nHKcke2mTMN+ssRuZ9NKGJZ
xMuL7OXn9kpYTA0SF3bZNZnuCTcHRKIldWRGcV/rPf2TrFO+QWZ/BHHFc9Ey5rAw
ANwt8noivSeQPpNALXM/+vGybpLL0juu1Tp5iMlIUEtPEQ4QTs2VUdNLGMQQ2mb2
Bfeih+MmGLOovez4hubBciiiZKE0jp3fa9OuD7odgIGNhC5YgNIQucGElcqh3L+D
fPZZq4lGxEY2HB+XG15vqgyg1ZYUQ5/mtqANmQ8n48JYvekjHP0aIE3/dgzWve7v
8w61X5WLAgMBAAECggEADd2cPejZ5ILXyGrTtVGRAidr8AIQElSMrkvWyRZL3mS8
1vWpL0T7lPAkVoJz62VloxeQJiCVQHAicxph3OUvfRBwmzzVjusACQpn7TyLOxtK
yfKY8Dq3zt5BcTrA1E4xM++ttKm1MmjaRZC4Gu40IRYHb9BCyjhIMI+/E+oDmT3t
mfyYe1YHz1t5YZEZ5QeQlLRpHnHsgFe1Q2ANwWwkqbXnWdCkwTfzUN/diikW4d8T
JFdQZsqS3thncBTFyr58PiCbw8Tj6Jr8ukA/A3pywRCJvohGzWCH+M3wagOV3l0c
X6gknCXKzk3WZKMaQF7deTXzm8H43F858ERUvc+YyQKBgQD4m+xy1DCZ9PH0aIZ1
b/hZ0dzeIq9mT3CGMwSLY3FSeAVnnflzTDeF5UdCUDNeUFEKvBGGmsrD8HANRqmr
1XFk6fJreuT+dfM5A34p1ywc8gzRH4Fa6NvfBgJ3oxfN83U9Hr5P/u6RVuNKrK/3
mHntwU8w5e6V1Qu1LHHGP1913QKBgQDl9ybIyFsR229n4owj2S8HeGZveSDkUDeC
EeF0NOb/CqZzYacvILiJw/81+C9O6SaMEMOi8n4L6wypWKUqhlB7JJYEih8LXqDG
aAbFu3gsYJbRELBz64GJROsDSJwhN/XJePq/5sC0Cvf+N4FWDKyh/xLe9VERUJX1
F7sZ5SZGhwKBgAeEv6vhWu7tB3w6xQY8MqiUvjdBmUhg0qhcVqDYiw7Rbmhp0Kd6
AJveCT+qKUOK7kiC04zclZFDbkAYiP0XYWyJ3rj9aHuBma95uZEOXtkpQNX6O/FB
5ZRjHCP+HLQvzrXgfiTxMsnWdN1HR7MXO2jDVd/GtGZ3oPkDtRUnyX1JAoGBAKUZ
Ypvl1BQm8X2o1Snrg+seEpTXZrjjqmZUhgNS88CJGeVeZ5PbLwGhWDmb/ALwOn92
ja4P4FSYJNfzz2iPU3qFUrrhmtYj0tN+3dXZ+LYLhluEWtpuauptMziBSa5Dqc9C
buuVNCZOdarqmI15vfrz0M2HW/NNYsu6hNZbgLZDAoGBANhLbENwHd3HZssN7ZEn
0rBdQ4LsRakEuEtGcDx3jwtCsLjAJDb8lyR6GT+C5zEXt/iMF6ePZR2MFSnitiDm
bUYm3BPmcU25IA5I3TuFELVEQm3dwFnr52EgbIAl8ov82Xs5FsNeVJTkvSsJwkA0
123eA1TsWT4CQ8db11u0Od5Z
-----END PRIVATE KEY-----`;
const awsSecret = 'wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY9xxx1';
const corpus: [string, string][] = [
    ['AWS ID', 'creds: AKIAQR7ZKT4MW2PLX9BD'],
    ['AWS secret and overlapping rules', `AWS_SECRET_ACCESS_KEY=${awsSecret}`],
    ['OpenAI', `key is sk-${'a'.repeat(20)}T3BlbkFJ${'b'.repeat(20)}`],
    ['GitHub', 'my github token is ghp_16C7e42F292c6912E7710c838347Ae178B4a'],
    ['bare GitHub', 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'],
    ['JWT', 'bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
        'eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c'],
    ['password', 'login: admin password: S0mmer2026!xTr0ub4dor'],
    ['bare password', 'password: S0mmer2026!xTr0ub4dor'],
    ['snake case', 'session_token: aB3xK9mQ2pL7wZ4v'],
    ['camel case', 'clientSecret=Zx9mK2pL7wQ4vB3xA1c'],
    ['database', 'postgres://admin:hunter2secret@db.example.com:5432/app'],
    ['Google', 'GOOGLE_API_KEY=AIza3EiODjfjghFw2GS6-hZByGzeM386y6zvl5f'],
    ['xAI', 'XAI_API_KEY=xai-Y7a1R_QjyDLgpFegN9uQL6yMqjhAl9bXEqgWZtj2dXWHMsj5y' +
        'skfHYLRe61tKKO_PW8NctSUR7m88X6R'],
    ['Google trailing hyphen', 'the deploy log mentions AIzaE3ZVSHDBs43BRT3PrSvZ0KshZJRhDBmCji- in passing'],
    ['Google oversized decoy', 'ref=AIzaX5wFmAbkO85TbATCmZwkKljQY9LVKxmYSf7e end'],
    ['comment bypass', '// secretlint-disable\npassword: S0mmer2026!xTr0ub4dor'],
    ['already redacted', 'password: [REDACTED:generic-keyword:4dor]'],
    ['independent hits', 'first: ghp_16C7e42F292c6912E7710c838347Ae178B4a then password: ' +
        'S0mmer2026!xTr0ub4dor'],
    ['short secret', 'pwd=Ab1!Ab1!'],
    ['below floor', 'short'],
    ['tiny', 'tiny'],
    ['50k', 'y'.repeat(50_000) + ' password: Qx7mP2vL9wZaB4nR8kFjT3hY6cWe1sNq'],
    ['150k negative', 'x'.repeat(150_000)],
    ['120k tail', 'z'.repeat(120_000) + ' clientSecret=Ab9cD3eF7gH1iJ5kL2mNoPqRsTuVwXyZ'],
    ['100k boundary', 'w'.repeat(99_970) + ' apiKey=Vr8tGq3mXpL6bWc9zNe2sYh5fKd1uAoI'],
    ['PEM boundary', 'w'.repeat(99_500) + `\n${pem}\ntrailer text`],
    ['2M cap fixture', 'password: Lk4pQw8eRt2yUi6oAs1dFg5hJz9xCvBn ' + 'q'.repeat(2_000_000) +
        ' password: Mo3nBv7cXz1lKj5hGf9dSa2wQe6rTy8u'],
    ['failure input', 'some message text'],
    ['JSON short password', 'abc123'],
    ['JSON single char', 'x'],
    ['JSON alias 1', 'v1'],
    ['JSON alias 2', 'v2'],
    ['JSON alias 3', 'v3'],
    ['JSON alias 4', 'v4'],
    ['JSON alias 5', 'v5'],
    ['JSON alias 6', 'v6'],
    ['JSON alias 7', 'v7'],
    ['JSON note', 'just a note'],
    ['JSON empty', ''],
    ['JSON structural ID', 'call_abc123'],
    ['JSON username', 'alice'],
    ['JSON array string', 'plain string'],
    ...negatives,
    // Core source normalization is observable at the range boundary.
    ['BOM', '\ufeffpassword: S0mmer2026!xTr0ub4dor'],
];

describe('runner parity against the original core configuration', () => {
    test.each(corpus)('%s', async (_label, content) => {
        const expected = await lintSource({
            source: { filePath: 'message.txt', content, ext: '.txt', contentType: 'text' },
            options: { config: { rules } },
        });
        expect(await scanText(content)).toEqual(
            expected.messages.map(({ ruleId, range }) => ({ ruleId, range })),
        );
    });
});
