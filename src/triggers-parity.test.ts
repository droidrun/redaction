/**
 * triggers-parity.test.ts — the cases of triggers-api's own redactor
 * (`redact-evidence.test.ts`, `step-input.test.ts`), run against the package.
 * Same inputs, same meaning: the same text is masked and the same text stays.
 * Only the marker differs: triggers wrote a bare `[REDACTED]`, the package
 * writes `[REDACTED:<rule>]`. Two documented limits of the triggers redactor
 * are lifted on purpose (the package also masks keyword pairs inside other
 * strings): see the `lifted` tests.
 */
import { describe, expect, test } from 'bun:test';
import { isSecretKeyName, redactJsonValueSync, redactTextSync } from './index.js';

const KW = '[REDACTED:generic-keyword]';
const AUTH = '[REDACTED:auth-header]';
const KEY = '[REDACTED:key-context]';
const redact = (text: string): string => redactTextSync(text).text;
const redactJson = (value: unknown): unknown => redactJsonValueSync(value);

describe('redactEvidence cases', () => {
    test('redacts bearer tokens', () => {
        expect(redact('Authorization: Bearer abc.def-1=')).toBe(`Authorization: Bearer ${AUTH}`);
    });

    test.each([
        ['password="my secret phrase" next', `password="${KW}" next`],
        ["password='my secret phrase' next", `password='${KW}' next`],
        ['{"api_key": "has space, and comma"}', `{"api_key": "${KW}"}`],
        ["{'secret': 'two words'}", `{'secret': '${KW}'}`],
        ['auth_token = "a b"', `auth_token = "${KW}"`],
        ['password="she said \\"hi there\\" ok" tail', `password="${KW}" tail`],
        ["secret='it''s fine' rest", `secret='${KW}''s fine' rest`],
    ])('quoted value with spaces: %s', (input, expected) => {
        expect(redact(input)).toBe(expected);
    });

    test('quoted values leave no fragment of the secret behind', () => {
        for (const q of ['"', "'"]) {
            const out = redact(`access_token=${q}top secret value${q}`);
            expect(out).not.toContain('top');
            expect(out).not.toContain('secret value');
            expect(out).not.toContain('value');
        }
    });

    test('unquoted and unterminated values are still redacted', () => {
        expect(redact('api_key=sk-live-1,next=2')).toBe(`api_key=${KW},next=2`);
        expect(redact('password: hunter2')).toBe(`password: ${KW}`);
        expect(redact('password="truncated-by-cut')).toBe(`password="${KW}`);
    });

    test('is idempotent', () => {
        const once = redact('password="a b" api_key=zzz Bearer q');
        expect(redact(once)).toBe(once);
    });

    test('leaves unrelated text alone', () => {
        const text = 'ValueError: boom password-reset flow ok';
        expect(redact(text)).toBe(text);
    });
});

describe('prepareStepInput: redaction by key name', () => {
    test('replaces nested values under secret key names, whatever their type', () => {
        const stored = redactJson({
            url: 'https://example.test',
            headers: { 'X-Api-Key': 'k-1', accept: 'json' },
            body: { user: { password: 'hunter2', profile: { apiKey: 'abc', client_secret: { id: 1 } } } },
            list: [{ accessToken: 't' }, { authToken: 't2' }],
        });
        expect(stored).toEqual({
            url: 'https://example.test',
            headers: { 'X-Api-Key': KEY, accept: 'json' },
            body: { user: { password: KEY, profile: { apiKey: KEY, client_secret: KEY } } },
            list: [{ accessToken: KEY }, { authToken: KEY }],
        });
    });

    test('masks Bearer tokens in strings anywhere in the structure', () => {
        const stored = redactJson({
            headers: { 'X-Forwarded': 'Bearer abc.def-ghi' },
            notes: ['x Bearer zzz y'],
        });
        expect(stored).toEqual({
            headers: { 'X-Forwarded': `Bearer ${AUTH}` },
            notes: [`x Bearer ${AUTH} y`],
        });
    });

    test('lifted: keyword pairs inside other strings are masked too', () => {
        // triggers kept `prompt: 'use password=hunter2'` ("documents its limit").
        expect(redactJson({ prompt: 'use password=hunter2', login: 'plain' }))
            .toEqual({ prompt: `use password=${KW}`, login: 'plain' });
    });

    test('a key named __proto__ stays a plain key', () => {
        const input = JSON.parse('{"__proto__":{"polluted":true},"a":1}');
        const stored = redactJson(input) as Record<string, unknown>;
        expect(Object.keys(stored)).toEqual(['__proto__', 'a']);
        expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });
});

describe('isSecretKeyName: words of the key, not substrings', () => {
    test.each([
        // the original set
        'password', 'Password', 'DB-PASSWORD', 'db_password', 'dbPassword', 'secret', 'clientSecret',
        'client_secret', 'secrets',
        'apiKey', 'api_key', 'API_KEY', 'api-key', 'APIKey', 'accessToken', 'access_token', 'authToken',
        'auth_token',
        // added
        'token', 'tokens', 'refresh_token', 'id_token', 'sessionToken', 'apiToken', 'x-auth-token',
        'X-Auth-Token',
        'authorization', 'Authorization', 'cookie', 'cookies', 'Set-Cookie', 'set_cookie', 'credential',
        'credentials',
        'privateKey', 'private_key', 'private key', 'PRIVATE-KEY', 'clientKey', 'client_key', 'client key',
        'passwd', 'passphrase', 'signature', 'Signature', 'cardNumber', 'card_number', 'card number',
        // exact names
        'pwd', 'otp', 'totp', 'pin', 'PIN', 'cvv', 'CVV', 'cvc',
        // one lower-case run
        'apikey', 'accesstoken', 'authtoken', 'privatekey', 'clientsecret', 'clientkey', 'cardnumber',
        'refreshtoken', 'setcookie',
        // contain the word: accepted
        'hasPassword', 'passwordPolicy', 'userPassword2', 'maxTokens',
        // absorbed from chat-agents-api
        'proxy-authorization', 'Proxy-Authorization',
    ])('%s is secret', (key) => {
        expect(isSecretKeyName(key)).toBe(true);
    });

    test.each([
        'name', 'prompt', 'url', 'key', 'keys', 'api', 'private', 'client', 'card', 'number', 'access',
        'auth',
        'secretary', 'passwordless', 'tokenizer', 'tokenization', 'cookbook', 'credentialed',
        'pinned', 'spin', 'pineapple', 'pins', 'pinCode', 'opt', 'options', 'cvvv', 'pwdx',
        'author', 'authorName', 'authority', 'authors', 'designature', 'passwordlessLogin',
    ])('%s is not secret', (key) => {
        expect(isSecretKeyName(key)).toBe(false);
    });
});

describe('prepareStepInput: authorization values in strings', () => {
    test('masks Bearer, Basic and Token values, keeping the scheme', () => {
        expect(redactJson({
            a: 'Bearer abc.def',
            b: 'Basic dXNlcjpwYXNzd29yZA==',
            c: 'Token 9f8e7d6c5b4a3210',
            e: 'basic dXNlcjpwYXNz',
        })).toEqual({
            a: `Bearer ${AUTH}`,
            b: `Basic ${AUTH}`,
            c: `Token ${AUTH}`,
            e: `basic ${AUTH}`,
        });
    });

    test('lifted: a token: label with a credential-shaped value is masked as a keyword pair', () => {
        // triggers kept `token: ghp_abcdef123456`; the keyword rule has evidence for it.
        expect(redact('token: ghp_abcdef123456')).toBe(`token: ${KW}`);
    });

    test('leaves prose that only contains the words alone', () => {
        const prose = {
            a: 'Token expired, Basic information, token refresh',
            b: 'Basic Authentication',
            c: 'use the token',
        };
        expect(redactJson(prose)).toEqual(prose);
    });
});

describe('prepareStepInput: redaction runs before size decisions', () => {
    test('a huge value under a secret key is replaced, not copied', () => {
        const big = { password: 'p'.repeat(1_000_000), keep: 1 };
        expect(redactJson(big)).toEqual({ password: KEY, keep: 1 });
    });
});
