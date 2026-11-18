/** The generator families. Each pushes cases through `add`; all randomness comes from the seeded rng. */
import { BASE62, chars, pick, type Rng } from './rng.ts';
import { FORMAT_SAMPLES, SCANNER_SAMPLES } from './samples.ts';
import type { CaseOpts, GenSpec } from './types.ts';

export type Add = (family: string, input: unknown, opts?: CaseOpts) => void;
export type AddGen = (family: string, gen: GenSpec, opts?: CaseOpts) => void;
export type Sinks = { add: Add; addGen: AddGen };

export const WORDS = [
    'the',
    'deploy',
    'failed',
    'user',
    'login',
    'ok',
    'retry',
    'secretary',
    'passwordless',
    'tokenizer',
    'Token',
    'expired',
    'Basic',
    'information',
    'bearer',
    'auth',
    'key',
    'id',
    'status',
    'name',
    'value',
    'https://example.test/path?page=2&sort=asc',
    'a-b-c',
    'x_y_z',
    'ünïcödé',
    '日本語',
    '😀',
    '{}',
    '[]',
    '[REDACTED]',
    '[REDACTED:key-context]',
    '[REDACTED:generic-keyword:4dor]',
    '"',
    "'",
    '\\',
    '\n',
    ':',
    '=',
    ',',
    'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB',
    '3fa85f64-5717-4562-b3fc-2c963f66afa6',
];
const SEPARATORS = [' ', ' ', '\n', ', ', '; ', '\t', ' | '] as const;

export const SECRET_KEYS = [
    'password',
    'apiKey',
    'api_key',
    'client_secret',
    'x-auth-token',
    'Authorization',
    'Set-Cookie',
    'accessToken',
    'refresh_token',
    'privateKey',
    'DB_PASSWORD',
    'sessionToken',
    'secret',
    'token',
    'cookie',
    'passphrase',
    'pin',
    'pwd',
    'max_tokens',
    'prompt_tokens',
    'cardNumber',
    'APIKey',
    'userpassword',
    'tokens',
    'secretary',
    'tokenizer',
    'passwordless',
    'sid',
    'code',
    'otp',
    'auth',
    'pass',
    'signature',
];
export const NEUTRAL_KEYS = [
    'name',
    'url',
    'prompt',
    'items',
    'body',
    'headers',
    'status',
    'note',
    'type',
    'id',
    '__proto__',
    'constructor',
];

export const CONTEXTS: ReadonlyArray<(m: string) => string> = [
    (m) => `password=${m}`,
    (m) => `password: ${m}`,
    (m) => `password="${m}"`,
    (m) => `api_key=${m},next=2`,
    (m) => `{"client_secret":"${m}","ok":true}`,
    (m) => `session_token: ${m}`,
    (m) => `Authorization: Bearer ${m}`,
    (m) => `Authorization: Basic ${m}`,
    (m) => `Authorization: Token ${m}`,
    (m) => `https://example.test/cb?token=${m}&x=1`,
    (m) => `https://example.test/v1?x=1&sig=${m}`,
    (m) => `AWS_SECRET_ACCESS_KEY=${m}`,
    (m) => `{"access_token": "${m}"}`,
    (m) => `{\\"password\\":\\"${m}\\",\\"ok\\":1}`,
    (m) => `{\\\\\\"client_secret\\\\\\":\\\\\\"${m}\\\\\\"}`,
    (m) => `postgres://user:${m}@db.example.test:5432/app`,
    (m) => `https://x.test/cb?redirect=https://y.test/?token=${m}&z=1`,
    (m) => `https://x.test/cb?redirect=https%3A%2F%2Fy.test%2F%3Ftoken%3D${m}&z=1`,
    (m) => `Cookie: sid=${m}; theme=dark`,
    (m) => `key dr_sk_${m} used`,
    (m) => `clientSecret: ${m}`,
    (m) => `secret='${m} with spaces'`,
    (m) => `credentials=${m}`,
    (m) => `private-key = ${m}`,
    (m) => `bearer:${m}`,
    (m) => `token=${m}&token=${m}`,
];

export function marker(rng: Rng): string {
    return `Zq9${chars(rng, BASE62, 14)}_x`;
}

function noise(rng: Rng, count: number): string[] {
    return Array.from({ length: count }, () => pick(rng, WORDS));
}

function join(rng: Rng, fragments: string[]): string {
    return fragments.map((f, i) => (i === 0 ? f : pick(rng, SEPARATORS) + f)).join('');
}

function textCase(rng: Rng): string {
    const fragments = noise(rng, Math.floor(rng() * 8));
    const contexts = 1 + Math.floor(rng() * 3);
    for (let i = 0; i < contexts; i++) {
        const at = Math.floor(rng() * (fragments.length + 1));
        fragments.splice(at, 0, pick(rng, CONTEXTS)(marker(rng)));
    }
    return join(rng, fragments);
}

function leaf(rng: Rng): unknown {
    const makers = [
        () => pick(rng, WORDS),
        () => Math.floor(rng() * 1e6),
        () => rng() < 0.5,
        () => null,
        () => '',
        () => join(rng, noise(rng, 3)),
        () => Math.floor(rng() * 1e6) / 100,
        () => 1e21,
        () => -7,
    ];
    return pick(rng, makers)();
}

function setKey(target: Record<string, unknown>, key: string, value: unknown): void {
    Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

function records(rng: Rng): unknown[] {
    const length = 1 + Math.floor(rng() * 4);
    return Array.from({ length }, (_, n) => ({
        id: `rec-${n}`,
        url: `https://h${n}.example.test/hook`,
        token: marker(rng),
        note: `n${n}`,
    }));
}

export function jsonValue(rng: Rng, depth: number): unknown {
    const roll = rng();
    if (depth <= 0 || roll < 0.25) return leaf(rng);
    if (roll < 0.35) return Array.from({ length: Math.floor(rng() * 4) }, () => jsonValue(rng, depth - 1));
    if (roll < 0.45) return records(rng);
    const out: Record<string, unknown> = {};
    const size = 1 + Math.floor(rng() * 4);
    for (let i = 0; i < size; i++) {
        const key = pick(rng, [...NEUTRAL_KEYS, ...SECRET_KEYS, '0', '7', '12', '4294967294', '4294967295']);
        const kind = rng();
        if (kind < 0.25) setKey(out, key, marker(rng));
        else if (kind < 0.4) setKey(out, key, { nested: [marker(rng), 'x'] });
        else if (kind < 0.55) setKey(out, key, pick(rng, CONTEXTS)(marker(rng)));
        else setKey(out, key, jsonValue(rng, depth - 1));
    }
    return out;
}

export function fuzzFamilies({ add }: Sinks, rng: Rng): void {
    for (let i = 0; i < 1500; i++) add('fuzz-text', textCase(rng));
    for (let i = 0; i < 1500; i++) add('fuzz-json', jsonValue(rng, 4));
    for (let i = 0; i < 300; i++) {
        const key = pick(rng, CONTEXTS)(marker(rng));
        add('fuzz-key', { [key]: 1, nested: { [key]: [{ [key]: 'x' }] } });
    }
    for (let i = 0; i < 300; i++) {
        const raw = Array.from({ length: Math.floor(rng() * 40) }, () => String.fromCharCode(rng() * 0xffff));
        add('fuzz-noise', raw.join(''));
    }
}

const JS_WHITESPACE = [
    '\t',
    '\n',
    '\v',
    '\f',
    '\r',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    ' ',
    '　',
    '﻿',
    '᠎',
    '\u0085',
    '​',
];

export function separatorFamilies({ add }: Sinks, rng: Rng): void {
    for (const space of JS_WHITESPACE) {
        const code = space.codePointAt(0)?.toString(16) ?? '';
        const m = marker(rng);
        add(`ws-${code}`, `password${space}=${space}${m}`);
        add(`ws-${code}`, `password:${space}${m}`);
        add(`ws-${code}`, `Authorization: Bearer${space}${m}`);
        add(`ws-${code}`, `Authorization: Basic${space}${m}`);
        add(`ws-${code}`, `Authorization: Token${space}${m}`);
        add(`ws-${code}`, `api_key${space}${space}=${space}"${m} a b"`);
        add(`ws-${code}`, `x${space}secret=${m}${space}tail`);
        add(`ws-${code}`, `https://x.test/cb?token=${m}${space}rest&a=1`);
        add(`ws-${code}`, `Cookie:${space}sid=${m}`);
        add(`ws-${code}`, `${space}${space}`.repeat(6) + `password=${m}`);
        add(`ws-${code}`, `secret=${m.slice(0, 5)}${space}${m.slice(5)}`);
        const pem = `-----BEGIN PRIVATE KEY-----${space}MIIEv${space}abc${space}-----END PRIVATE KEY-----`;
        add(`ws-${code}`, pem);
        add(`ws-${code}`, { password: `${space}${m}${space}`, note: `token${space}:${space}${m}` });
    }
}

const PREFIXES = [
    '',
    'a',
    '_',
    '-',
    '0',
    'Z',
    '😀',
    '\ud800',
    '\udc00',
    'AIza',
    'xai-',
    'eyJ',
    'ghp_',
    'sk-',
    'sk-ant-',
    ':',
    '"',
    '=',
    ' ',
    ' ',
    '﻿',
    'Bearer ',
    'password=',
    'token: ',
    '?',
    '&',
    '/',
    '@',
    '\\',
    '[REDACTED:x]',
    'ab.',
    'x-',
    'srt1.',
    'dr_sk_',
];
const SUFFIXES = ['', '-', '_', 'a', '.', ' ', '=', ',', '😀', '\ud800', '"', '\\', '&x=1', '\n'];

export function prefixFamilies({ add }: Sinks): void {
    const samples = [...FORMAT_SAMPLES, ...SCANNER_SAMPLES];
    for (const sample of samples) {
        for (const prefix of PREFIXES) add('prefix', `${prefix}${sample}`);
        for (const suffix of SUFFIXES) add('suffix', `ok ${sample}${suffix}`);
        add('sample', sample);
        add('sample', { nested: [{ text: sample }], note: sample });
        add('sample', { password: sample, [sample]: 1 });
    }
}

const ASTRAL = ['😀', '🧑‍💻', '𝒳', '\u{10ffff}', '\ud83d', '\ude00', 'é', 'é'];

export function astralFamilies({ add }: Sinks, rng: Rng): void {
    for (const ch of ASTRAL) {
        for (const context of CONTEXTS) {
            const m = marker(rng);
            add('astral', `${ch}${ch}${context(m)}${ch}`);
            add('astral', `${context(`${ch}${m}${ch}`)} ${ch}`);
        }
    }
    for (let n = 1; n <= 12; n++) {
        const m = marker(rng);
        add('astral-offset', `${'😀'.repeat(n)}password=${m}`);
        add('astral-offset', `password=${'😀'.repeat(n)}${m}`);
        add('astral-offset', `api_key="${'𝒳'.repeat(n)}${m}"`);
    }
}

export function jsonShapeFamilies({ add }: Sinks, rng: Rng): void {
    for (let i = 0; i < 60; i++) {
        const m = marker(rng);
        const body: Record<string, unknown> = { b: m, 2: 'two', 1: { token: m }, a: [m], 10: m, 0: 'z' };
        add('int-keys', body);
        add('int-keys', { 3: m, 1: m, password: m, 2: { 9: m, 8: `password=${m}` } });
        add('int-keys', { '01': m, '1': m, '-1': m, '1.5': m, '4294967295': m, '4294967294': m });
    }
    for (let i = 0; i < 60; i++) {
        const a = `password=${marker(rng)}`;
        const b = `password=${marker(rng)}`;
        add('key-collision', { [a]: 1, [b]: 2 });
        add('key-collision', { [`token ${a}`]: 'x', [`token ${b}`]: 'y', other: 1 });
        add('key-collision', { '[REDACTED:generic-keyword]': 1, [a]: 2 });
    }
    for (const depth of [1, 2, 3, 8, 16, 63, 64, 65, 66, 70, 100]) {
        let arr: unknown = { token: marker(rng), text: `password=${marker(rng)}` };
        let obj: unknown = arr;
        for (let i = 0; i < depth; i++) {
            arr = [arr];
            obj = { child: obj };
        }
        add('depth', arr);
        add('depth', obj);
        for (const maxDepth of [0, 1, 2, depth - 1, depth, depth + 1, depth + 2]) {
            if (maxDepth >= 0) add('depth-cap', obj, { maxDepth });
        }
    }
}

export function capFamilies({ add }: Sinks, rng: Rng): void {
    const values = [`password=${marker(rng)}`, 'x'.repeat(30), `${marker(rng)}`, 'ab'.repeat(8)];
    for (const value of values) {
        for (const delta of [-2, -1, 0, 1, 2]) {
            add('maxchars-text', value, { maxChars: value.length + delta });
            add('maxchars-json', { a: value, b: [value, value] }, { maxChars: value.length * 3 + delta });
            add('maxchars-leaf', { a: value, b: value }, { maxChars: value.length + delta });
        }
    }
    const tree = {
        a: [1, 2, 3, { b: 'x', c: [4, 5] }],
        d: { e: marker(rng), f: null },
        g: 'tail value here',
    };
    for (let nodes = 0; nodes <= 16; nodes++) add('maxnodes', tree, { maxNodes: nodes });
    for (let n = 0; n < 25; n++) {
        const key = `${'k'.repeat(n * 40 + 1)}`;
        add('wide', { [key]: marker(rng) });
    }
    for (const length of [6, 7, 8, 9]) {
        add('min-scan', `a=${'b'.repeat(length - 2)}`);
        add('min-scan', 'x'.repeat(length));
        add('min-key', { [`password`.slice(0, length)]: 'q' });
        add('min-key', { [`k${'0'.repeat(length - 1)}`]: `Bearer ${marker(rng)}` });
    }
    for (const length of [4094, 4095, 4096, 4097, 4098]) {
        const key = `password=${marker(rng)}`.padEnd(length, 'k');
        add('key-cap', { [key]: 1 });
    }
    for (const skipKeys of [[], ['type'], ['id', 'url'], ['password'], ['nested']]) {
        const m = marker(rng);
        const value = { type: m, id: m, url: `password=${m}`, password: m, nested: { id: m, deep: [m] } };
        add('skip-keys', value, { skipKeys });
    }
}

function repeated(unit: string, times: number): string {
    return unit.repeat(times);
}

export function boundaryFamilies({ add }: Sinks, rng: Rng): void {
    const base = (n: number): string => chars(rng, `${BASE62}_`, n);
    for (const length of [6, 7, 8, 9, 255, 256, 257, 258, 300, 1000]) {
        add('value-window', `password=${base(length)}`);
        add('value-window', `{"api_key":"${base(length)}"}`);
        add('value-window', `secret: ${base(length)} tail`);
    }
    for (const length of [1022, 1023, 1024, 1025, 1026, 4000]) {
        const body = repeated('a b,', length / 4).slice(0, length);
        add('quote-limit', `password="${body}"`);
        add('quote-limit', `password="${body}`);
        add('quote-limit', `secret='${body}' tail`);
        add('quote-limit', `{\\"api_key\\":\\"${body}\\"}`);
    }
    for (const length of [62, 63, 64, 65, 66]) {
        const tail = 'a'.repeat(length);
        add('keyword-tail', `token${tail}=${base(20)}`);
        add('keyword-tail', `xx${'a'.repeat(length)}_token: ${base(20)}`);
        add('label-start', `${'q'.repeat(length)}token=${base(20)}`);
        add('label-start', `?${'q'.repeat(length)}token=${base(20)}&b=${base(9)}`);
    }
    for (const length of [34, 35, 36, 37]) add('gcp', `AIza${chars(rng, `${BASE62}_-`, length)}`);
    for (const length of [78, 79, 80, 81, 82]) add('xai', `xai-${chars(rng, `${BASE62}_`, length)}`);
    for (const length of [9, 10, 11, 12]) {
        add('jwt', `eyJ${chars(rng, `${BASE62}_-`, length)}.${base(length)}.${base(12)}`);
    }
    for (const length of [20, 21, 22, 36, 37, 254, 255, 256, 257]) {
        add('github', `ghp_${chars(rng, BASE62, length)}`);
        add('github', `github_pat_${chars(rng, `${BASE62}_`, length)}`);
    }
    for (const length of [8, 9, 10, 199, 200, 201, 202]) {
        add('slack', `xoxb-${chars(rng, `${BASE62}-`, length)}`);
    }
    for (const length of [6, 7, 8, 9]) add('platform-key', `dr_sk_${base(length)}`);
    for (const length of [15, 16, 17, 18]) {
        add('aws', `AKIA${chars(rng, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', length)}`);
        add('stripe', `sk_live_${chars(rng, BASE62, length)}`);
    }
    for (const length of [18, 19, 20, 21]) add('sk', `sk-${chars(rng, `${BASE62}_-`, length)}`);
    for (const length of [0, 1, 40, 41, 42]) {
        const label = 'A'.repeat(length);
        add('pem-header', `-----BEGIN ${label}PRIVATE KEY-----\nMIIEv\n-----END PRIVATE KEY-----`);
    }
    for (const length of [8190, 8191, 8192, 8193, 9000]) {
        const body = 'ab+/ '.repeat(length / 5);
        add('pem-body', `-----BEGIN PRIVATE KEY-----${body}\n-----END PRIVATE KEY-----`);
        add('pem-body', `-----BEGIN PRIVATE KEY-----${body} ## after`);
    }
    for (const length of [126, 127, 128, 129, 130]) {
        add('query-key', `https://x.test/?${'k'.repeat(length)}=v&token=${base(12)}`);
        add('userinfo', `https://${'u'.repeat(length)}:${base(10)}@h.test/`);
    }
    for (const length of [29, 30, 31, 32, 33]) add('scheme', `${'a'.repeat(length)}://u:${base(10)}@h.test/`);
    for (const length of [4094, 4095, 4096, 4097, 4098]) {
        const value = `${'%41'.repeat(length / 3)}`.slice(0, length);
        add('nested-query', `https://x.test/?r=${value}%3Ftoken%3D${base(12)}`);
        add('nested-query', `https://x.test/?r=${'a'.repeat(length - 30)}%3Ftoken%3D${base(12)}&z=1`);
    }
    add('percent-bad', 'https://x.test/?r=%E0%A4%A&token=Zq9abcDEF123');
    add('percent-bad', 'https://x.test/?r=%ZZ%3Ftoken%3DZq9abcDEF123&q=1');
    add('percent-bad', 'https://x.test/?%74oken=Zq9abcDEF123&%E0%A4%A=1');
}

export function largeFamilies({ addGen }: Sinks): void {
    const secret = 'password=Zq9abcDEF123ghi_x';
    const jwt = FORMAT_SAMPLES[1] as string;
    addGen('large', {
        parts: [
            ['lorem ipsum ', 8000],
            [secret, 1],
            [' tail ', 3],
        ],
    });
    addGen('large-window', {
        parts: [
            ['abcdefghi ', 8976],
            [' ', 0],
            [jwt, 1],
            ['xyz ', 4],
        ],
    });
    addGen('large-window', {
        parts: [
            ['abcdefghi ', 9975],
            [`${SCANNER_SAMPLES[0]}`, 1],
            [' z', 1],
        ],
    });
    addGen('large-window', {
        parts: [
            ['abcdefghi ', 8970],
            [`${SCANNER_SAMPLES[1]}`, 1],
            [' z', 1],
        ],
    });
    addGen('large-window', {
        parts: [
            ['ab ', 33300],
            [`${SCANNER_SAMPLES[3]}`, 1],
            [' z', 1],
        ],
    });
    addGen('large-pem', {
        parts: [
            ['-----BEGIN PRIVATE KEY-----', 1],
            ['ab cd ', 20000],
        ],
    });
    addGen('large-cap', {
        parts: [
            ['ab ', 666700],
            [`${SCANNER_SAMPLES[0]}`, 1],
            [' ', 1],
            [secret, 1],
        ],
    });
    const npm = `${SCANNER_SAMPLES[0]}`;
    addGen('large-cap', {
        parts: [
            ['ab ', 666663],
            [' ', 1],
            [npm, 1],
            [' ', 1],
            [secret, 1],
        ],
    });
    addGen('large-default-cap', {
        parts: [
            ['ab ', 1333334],
            [secret, 1],
        ],
    });
}

const KEYWORD_WORDS = [
    'password',
    'passwd',
    'pwd',
    'secret',
    'token',
    'api_key',
    'api-key',
    'apikey',
    'access_key',
    'client_secret',
    'private_key',
    'privatekey',
    'credentials',
    'credential',
    'authorization',
    'bearer',
    'access_token',
    'auth_token',
    'TOKEN',
    'Password',
    'API_KEY',
    'sessionToken',
    'x-auth-token',
];

export function keywordMatrixFamilies({ add }: Sinks, rng: Rng): void {
    const value = (length: number): string =>
        `Zq9${chars(rng, BASE62, Math.max(0, length - 3))}`.slice(0, length);
    for (const word of KEYWORD_WORDS) {
        for (const length of [7, 8, 9, 20, 255, 256, 257, 300]) {
            add('kw-matrix', `${word}=${value(length)}`);
            add('kw-matrix', `${word}: ${value(length)} tail`);
            add('kw-matrix', `?${word}=${value(length)}&b=1`);
            add('kw-matrix', `{"${word}":"${value(length)}"}`);
        }
        for (const shape of [
            'abcdefgh',
            'ABCDEFGH',
            '12345678',
            'abcd1234',
            'aB3$xYz9',
            'Zq9-x',
            'aaaaaaaaaaaaaaaa',
            'abcdefghijklmnopqrstuvwxyz',
            'correct-horse-battery-staple',
            'your_api_key_here',
            'xxxxxxxx',
            '********',
            '<placeholder>',
            '{{secret}}',
            'undefined',
            'changeme',
            'REPLACE_ME_TOKEN',
            '"quoted1A"',
        ]) {
            add('kw-shape', `${word}=${shape}`);
            add('kw-shape', `${word}: ${shape}`);
            add('kw-shape', `${word}="${shape}"`);
        }
    }
}

const KEY_WORD_LISTS = {
    sequences: [
        ['api', 'key'],
        ['access', 'token'],
        ['auth', 'token'],
        ['password'],
        ['secret'],
        ['token'],
        ['authorization'],
        ['cookie'],
        ['credential'],
        ['private', 'key'],
        ['client', 'key'],
        ['access', 'key'],
        ['passwd'],
        ['passphrase'],
        ['signature'],
        ['card', 'number'],
        ['basic', 'auth'],
        ['priv', 'key'],
        ['signing', 'key'],
        ['encryption', 'key'],
        ['master', 'key'],
        ['ssh', 'key'],
        ['service', 'account', 'key'],
        ['dsn'],
        ['connection', 'string'],
        ['recovery', 'code'],
    ],
    exact: [
        'pwd',
        'otp',
        'totp',
        'pin',
        'cvv',
        'cvc',
        'sig',
        'jwt',
        'pass',
        'auth',
        'sid',
        'code',
        'session',
    ],
    joined: ['clientsecret', 'refreshtoken', 'idtoken', 'sessiontoken', 'apitoken', 'setcookie', 'privkey'],
    suffix: [
        'password',
        'passwd',
        'passphrase',
        'secret',
        'token',
        'apikey',
        'accesskey',
        'privatekey',
        'credential',
        'pwd',
    ],
    prefix: [
        'secretkey',
        'accesskey',
        'privatekey',
        'apikey',
        'clientsecret',
        'authtoken',
        'accesstoken',
        'refreshtoken',
        'signingkey',
        'encryptionkey',
        'masterkey',
        'sshkey',
        'serviceaccountkey',
        'connectionstring',
        'recoverycodes',
        'basicauth',
        'privkey',
    ],
    count: [
        'count',
        'limit',
        'max',
        'min',
        'total',
        'usage',
        'used',
        'budget',
        'num',
        'size',
        'length',
        'ttl',
        'expires',
        'expiry',
        'age',
        'rate',
        'quota',
        'remaining',
    ],
};

function keyForms(parts: string[]): string[] {
    const cap = (word: string): string => word.charAt(0).toUpperCase() + word.slice(1);
    const [first = ''] = parts;
    return [
        parts.join('_'),
        parts.join('-'),
        parts.join(''),
        parts.map(cap).join(''),
        first + parts.slice(1).map(cap).join(''),
        parts.join('.'),
        parts.join('_').toUpperCase(),
        `my_${parts.join('_')}`,
        `${parts.join('_')}_x`,
        `x${parts.join('')}`,
        `${parts.join('')}s`,
        `${parts.join('_')}s`,
        `${parts.join('')}x`,
        `${parts.join('')}_id`,
    ];
}

export function keyListFamilies({ add }: Sinks): void {
    const probe = (key: string): void => {
        add('key-probe', { [key]: 'Zq9secretvalue', n: { [key]: 1234 }, list: [{ [key]: [1, 'a b'] }] });
    };
    for (const parts of KEY_WORD_LISTS.sequences) for (const key of keyForms(parts)) probe(key);
    for (const word of [...KEY_WORD_LISTS.exact, ...KEY_WORD_LISTS.joined])
        for (const key of keyForms([word])) probe(key);
    for (const word of [...KEY_WORD_LISTS.suffix, ...KEY_WORD_LISTS.prefix]) {
        for (const key of [
            word,
            `user${word}`,
            `${word}key`,
            `${word}id`,
            `${word}s`,
            `x_${word}`,
            `${word}Value`,
        ]) {
            probe(key);
        }
    }
    for (const count of KEY_WORD_LISTS.count) {
        for (const base of ['token', 'password', 'api_key', 'secret']) {
            probe(`${count}_${base}`);
            probe(`${base}_${count}`);
            probe(`${base}${count.charAt(0).toUpperCase()}${count.slice(1)}`);
        }
    }
    for (const key of [
        'APIKey',
        'APIkey',
        'aPIKey',
        'ABc',
        'AB',
        'A1b',
        'a1B2',
        'ÜberToken',
        'tokén',
        'pİn',
        'p\u212An',
        '',
        ' ',
        '__token__',
        'Token-',
        '-token',
        'tOKEN',
        'TOKen',
        'sessionTOKEN',
        'x-API-KEY',
        'X_Auth-Token',
    ]) {
        probe(key);
    }
}

const QUERY_KEYS = [
    'code',
    'sid',
    'session',
    'otp',
    'pwd',
    'CODE',
    'Sid',
    'SESSION',
    'token',
    'sig',
    'page',
    'q',
];

export function queryFamilies({ add, addGen }: Sinks, rng: Rng): void {
    const m = (): string => marker(rng);
    for (const key of QUERY_KEYS) {
        add('query-key', `https://x.test/cb?${key}=${m()}&z=1`);
        add('query-key', `https://x.test/cb?a=1&${key}=${m()}#frag`);
        add('query-key', `https://x.test/cb?r=a%3F${key}%3D${m()}%26z%3D1`);
        add('query-key', `https://x.test/cb?%${key.length > 0 ? '63' : '00'}ode=${m()}`);
    }
    for (const [name, wrap] of [
        ['dq', '"'],
        ['sq', "'"],
        ['lt', '<'],
        ['gt', '>'],
        ['hash', '#'],
        ['amp', '&'],
        ['sp', ' '],
        ['nl', '\n'],
    ] as const) {
        add('query-end', `https://x.test/?token=${m()}${wrap}rest`);
        add('query-end', `https://x.test/?r=a%3Ftoken%3D${m()}${wrap}rest`);
        add('query-end', `https://x.test/?r=a%3Ftoken%3D${m()}${wrap}rest&${name}=1`);
    }
    for (const length of [4094, 4095, 4096, 4097]) {
        add('query-nested', `?r=${'a'.repeat(length - 40)}%3Ftoken%3D${m()}&z=1`);
        add('query-nested', `?r=%3Ftoken%3D${'a'.repeat(length)}&z=1`);
    }
    const piece = `?r=${'a'.repeat(3900)}%3Ftoken%3D1&z=1`;
    addGen('query-budget', {
        parts: [
            [piece, 255],
            [`?r=%3Ftoken%3D${marker(rng)}`, 1],
        ],
    });
    addGen('query-budget', {
        parts: [
            [piece, 257],
            [`?r=%3Ftoken%3D${marker(rng)}`, 1],
        ],
    });
    addGen('query-budget', {
        parts: [
            [piece, 300],
            [`?token=${marker(rng)}`, 1],
        ],
    });
}

export function schemeFamilies({ add }: Sinks, rng: Rng): void {
    const values = [
        'abcdefgh',
        'ABCDEFGH',
        'Abcdefgh',
        'Abcdefgh1',
        'abcdefg',
        'abcdefghi.',
        'abcdefghi-x',
        'abcdefgh_',
        'abcdefgh=',
        'Abcdefgh=',
        'Abc',
        'aB3d5F7h',
        'dXNlcjpwYXNz',
        'ABCDEFGH1',
        '12345678',
        'x1y2z3w4',
        'a.b.c.d.e.f',
        'Missing',
        'tokens',
        'required',
        'header',
        'authentication',
        'Zq9abcDEF123',
    ];
    for (const scheme of [
        'Basic',
        'basic',
        'BASIC',
        'Token',
        'token',
        'TOKEN',
        'bAsic',
        'Bearer',
        'bearer',
        'BEARER',
    ]) {
        for (const value of values) {
            add('scheme', `Authorization: ${scheme} ${value}`);
            add('scheme', `${scheme} ${value} and more`);
            add('scheme', `${scheme}\t${value}`);
        }
    }
    add('scheme', `Authorization: Basic ${'a1'.repeat(300)}`);
    add('scheme', `Basic  ${marker(rng)}`);
}

export function wordFamilies({ add }: Sinks, rng: Rng): void {
    const stands = [
        'undefined',
        'null',
        'changeme',
        'example',
        'placeholder',
        'password',
        'secret',
        'token',
        'Undefined',
        'NULL',
        'to\u212Aen',
        'x',
        'xX',
        'XXXXXXXX',
        '*',
        '*****',
        '<>',
        '<a>',
        '< >',
        '<a\nb>',
        '<a\u2028b>',
        '{}',
        '{a}',
        '{{x}}',
        '{a\rb}',
        '  null  ',
        '\u00a0null\u00a0',
        'your_x',
        'my-x',
        'the_x',
        'replace_me',
        'insert-here',
        'example_x',
        'dummy_value',
        'sample-key',
        'x_here',
        'x-here',
        'HERE',
        'a_HERE',
        'your',
        'your_',
        'yourx',
        'Your_Key',
        'URL_here',
        'a_here_b',
        'k_Here',
        'Zq9-correct-horse-battery-staple',
        'correct-horse-battery-staple',
        'aaaaaaaabbbbbbbbccccccccdddddddd',
        'abababababababab',
        'abcdefghijklmnop',
        'abcdefghijklmnopqrstuvwxyz0123456789',
        'The quick brown',
        'zxcvbnmasdfghjkl',
        "'abcdefgh'",
        '"x"',
        '"',
        "'",
        '""',
        'ab"',
        '"abc',
        '[REDACTED]',
        '[REDACTED:x]',
        '[REDACTED:x:ab12]',
        '[REDACTED:a b]',
    ];
    for (const stand of stands) {
        add('stand-in', `password=${stand}`);
        add('stand-in', `password: "${stand}"`);
        add('stand-in', `session_token=${stand}${stand}`);
        add('stand-in', `api_key = '${stand} '`);
        add('stand-in', { password: stand, nested: { text: `token=${stand}` } });
    }
    for (let n = 0; n < 40; n++)
        add('stand-in', `secret=${chars(rng, 'abcdefghijklmnopqrstuvwxyz_-', 16 + n)}`);
}

function entropyOf(text: string): number {
    const frequencies = new Map<string, number>();
    for (const char of text) frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
    let entropy = 0;
    for (const count of frequencies.values()) {
        const p = count / text.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

/** Two-class values whose entropy lies just below and just above the evidence threshold. */
function entropyValues(rng: Rng): string[] {
    const found: string[] = [];
    const windows: Array<[number, number]> = [
        [3.3, 3.35],
        [3.35, 3.4],
        [3.4, 3.45],
        [3.45, 3.5],
    ];
    for (const [low, high] of windows) {
        for (
            let attempts = 0;
            attempts < 200000 && found.filter((v) => entropyOf(v) >= low && entropyOf(v) < high).length < 3;
            attempts++
        ) {
            const alphabet = 'abcdefghijklmnopqrstuvwxyz'.slice(0, 8 + Math.floor(rng() * 6));
            const candidate = chars(rng, alphabet, 14 + Math.floor(rng() * 14));
            if (entropyOf(candidate) >= low && entropyOf(candidate) < high) found.push(candidate);
        }
    }
    return found;
}

export function thresholdFamilies({ add, addGen }: Sinks, rng: Rng): void {
    for (const value of entropyValues(rng)) {
        add('entropy', `password=${value}`);
        add('entropy', `secret: ${value}`);
        add('entropy', `session_token=${value}`);
    }
    for (const word of [
        'api',
        'apikey',
        'access',
        'accessx',
        'client',
        'private',
        'privatex',
        'credentialx',
        'credentialsx',
        'authorizationx',
        'bearerx',
        'key',
        'tok',
        'pass',
        'passw',
        'secre',
        'pw',
    ]) {
        add('kw-near', `${word}=Zq9abcdefgh1`);
        add('kw-near', `${word}_value: Zq9abcdefgh1`);
        add('kw-near', `${word}: Zq9abcdefgh1`);
    }
    for (const word of [
        'token',
        'tokens',
        'auth',
        'authentication',
        'header',
        'scheme',
        'missing',
        'invalid',
        'required',
        'Token',
        'TOKEN',
        'Invalid',
    ]) {
        add('auth-plain', `Bearer ${word}`);
        add('auth-plain', `Authorization: Bearer ${word} for user`);
        add('auth-plain', `bearer ${word}.`);
    }
    for (const text of ['Bearer x', 'bearer xy', 'BEARER z', 'Bearer  ', 'Bearer\tq', 'Bearer a1']) {
        add('min-scan', text);
        add('min-scan', { [text]: 1 });
    }
    for (const prefix of [
        'your',
        'my',
        'the',
        'replace',
        'insert',
        'example',
        'dummy',
        'sample',
        'yourk',
        'mine',
    ]) {
        for (const separator of ['_', '-', '.', '']) {
            add('doc-prefix', `secret=${prefix}${separator}abcdefghijkl`);
            add('doc-prefix', `secret=${prefix}${separator}aabbaabbaabb`);
        }
        add('doc-prefix', `secret=${prefix.toUpperCase()}_Abcdefghijkl`);
    }
    for (const separator of ['_', '-', '.', '']) {
        add('doc-suffix', `secret=aabbaabbaabb${separator}here`);
        add('doc-suffix', `secret=aabbaabbaabb${separator}HERE`);
    }
    // A GitHub app token is the one scanner shape longer than the window overlap (up to 12,000
    // units): these two are just too long for any scan window, or just fit the next one.
    const appToken = (lead: number, middle: number): GenSpec => ({
        parts: [
            [' ', lead],
            ['ghs_1_', 1],
            ['a', 1000],
            ['.', 1],
            ['b', middle],
            ['.', 1],
            ['c', 1000],
            [' tail', 1],
        ],
    });
    addGen('window-edge', appToken(89000, 8993));
    addGen('window-edge', appToken(89759, 8234));
    addGen('window-edge', appToken(89760, 8234));
    addGen('window-edge', appToken(1000, 8993));
    const piece = `?r=${'a'.repeat(1000)}&`;
    addGen('query-budget', {
        parts: [
            [piece, 1000],
            ['?r=%3Ftoken%3DZq9abcdefgh1', 1],
        ],
    });
    addGen('query-budget', {
        parts: [
            [piece, 999],
            ['?r=%3Ftoken%3DZq9abcdefgh1', 1],
        ],
    });
    addGen('large-default-cap', {
        parts: [
            ['ab ', 1333333],
            ['a', 1],
            ['password=Zq9abcDEF123ghi_x', 0],
        ],
    });
    addGen('large-default-cap', {
        parts: [
            ['ab ', 1333333],
            ['a', 2],
        ],
    });
    addGen('large-default-cap', {
        parts: [
            ['ab ', 1333333],
            ['a', 1],
            [' ', 0],
        ],
    });
    const npm = `${SCANNER_SAMPLES[0]}`;
    for (const lead of [1999959, 1999960, 1999961, 1999962]) {
        addGen('large-cap', {
            parts: [
                [' ', lead],
                [npm, 1],
                [' tail', 1],
            ],
        });
    }
    for (const end of [99999, 100000, 100001, 189758, 189759, 189760, 189761]) {
        addGen('large-window', {
            parts: [
                [' ', end - npm.length],
                [npm, 1],
                [' tail ', 20000],
            ],
        });
    }
    for (const comment of [
        '# secretlint-disable',
        '// secretlint-disable-next-line',
        '<!-- secretlint-disable -->',
        '/* secretlint-disable */',
        '# secretlint-disable-line',
    ]) {
        add('comment-filter', `${comment}\n${SCANNER_SAMPLES[0]}\n${SCANNER_SAMPLES[1]}`);
        add('comment-filter', `${SCANNER_SAMPLES[2]} ${comment}\n${SCANNER_SAMPLES[3]}`);
    }
}

export function subsequenceKeyFamilies({ add }: Sinks): void {
    for (const parts of KEY_WORD_LISTS.sequences) {
        for (let from = 0; from < parts.length; from++) {
            for (let to = from + 1; to <= parts.length; to++) {
                if (to - from === parts.length) continue;
                const sub = parts.slice(from, to);
                for (const key of [sub.join('_'), `x_${sub.join('_')}`, sub.join('')]) {
                    add('key-sub', { [key]: 'Zq9secretvalue', n: { [key]: 1234 } });
                }
            }
        }
    }
}

const FIXED_MARKER = 'Zq9abcDEF123ghi_x';
const FOLDS: Array<[from: string, to: string]> = [
    ['k', 'K'],
    ['K', 'K'],
    ['s', 'ſ'],
    ['S', 'ſ'],
    ['i', 'İ'],
    ['I', 'İ'],
    ['i', 'ı'],
    ['l', 'ℓ'],
];

/** Case-fold characters (Kelvin sign, long s, dotted capital I, dotless i) inside every context and key. */
export function foldFamilies({ add }: Sinks): void {
    for (const context of CONTEXTS) {
        const text = context(FIXED_MARKER);
        for (const [from, to] of FOLDS) {
            add('fold', text.replace(from, to));
            add('fold', text.split(from).join(to));
        }
        add('fold', text.toUpperCase());
        add('fold', text.toLowerCase());
    }
    for (const key of [...SECRET_KEYS, 'Cookie', 'Set-Cookie', 'BASIC', 'Basic', 'TOKEN', 'Token']) {
        for (const [from, to] of FOLDS) {
            const folded = key.replace(from, to);
            if (folded === key) continue;
            add('fold-key', { [folded]: FIXED_MARKER, nested: { [folded]: [FIXED_MARKER] } });
            add('fold-key', `${folded}: ${FIXED_MARKER}`);
        }
    }
    for (const word of ['Basic', 'BASIC', 'Token', 'TOKEN', 'Bearer', 'bearer']) {
        for (const [from, to] of FOLDS) {
            add('fold-scheme', `Authorization: ${word.replace(from, to)} ${FIXED_MARKER}`);
        }
    }
}

const WRAPPER_INNERS = [
    '\u{1f511}',
    '\u{1f600}',
    '\ud83d',
    '\ude00',
    '\ud83d\ud83d',
    'ab\u{1f600}cd',
    '\u{1f600}'.repeat(4),
    'abcdefg\u{1f600}',
    '\u{1f600}abcdefg',
    ' ',
    ' ',
    'a\nb',
    'a\rb',
    '',
    ' ',
    'é',
    'x'.repeat(10),
];

/** Astral characters and lone surrogates inside the stand-in wrappers `<...>` and `{...}`. */
export function wrapperFamilies({ add }: Sinks): void {
    for (const inner of WRAPPER_INNERS) {
        for (const [open, close] of [
            ['<', '>'],
            ['{', '}'],
            ['{{', '}}'],
            ['<', '}'],
            ['(', ')'],
        ] as const) {
            const value = `${open}${inner}${close}`;
            add('wrapper', `password=${value}`);
            add('wrapper', `password="${value}"`);
            add('wrapper', `secret: ${value} tail`);
            add('wrapper', `api_key='${value}'`);
            add('wrapper', { token: value, password: [value], note: `token=${value}` });
            add('wrapper', `Authorization: Bearer ${value}`);
        }
    }
}

/** What stops a cookie value: escapes `\n \r \" \'` in both cases, and every other escape. */
export function cookieEscapeFamilies({ add }: Sinks): void {
    const escapes = ['n', 'N', 'r', 'R', '"', "'", '\\', 'x', 'X', 't', 'u', 'K', ' '];
    for (const prefix of ['Cookie: ', 'Set-Cookie: ', 'COOKIE: ', 'cookie:\t', 'Set_Cookie: ']) {
        for (const escape of escapes) {
            add('cookie-escape', `${prefix}a=b\\${escape}xyz tail`);
            add('cookie-escape', `${prefix}a=b\\${escape}`);
            add('cookie-escape', `${prefix}\\${escape}a=b`);
            add('cookie-escape', `{"h":"${prefix}a=b\\\\${escape}xyz"}`);
        }
    }
}

/** Final line terminators after a placeholder value, the JS `$` exception of the whole-placeholder test. */
export function placeholderEndFamilies({ add }: Sinks): void {
    for (const end of ['', '\n', '\r', ' ', ' ', '\n\n', '\r\n', ' ', ' ', '\u0085']) {
        for (const placeholder of [
            '[REDACTED]',
            '[REDACTED:key-context]',
            '[REDACTED:generic-keyword:4dor]',
        ]) {
            const value = `${placeholder}${end}`;
            add('placeholder-end', { token: value, password: [value, { secret: value }], note: value });
            add('placeholder-end', `password=${value}`);
            add('placeholder-end', `password: "${value}"`);
            add('placeholder-end', `Authorization: Bearer ${value}`);
            add('placeholder-end', { [`${placeholder}${end}`]: 1, token: 'x' });
        }
    }
}

/** Astral characters and lone surrogates directly beside every sample: every lookaround and class edge. */
export function guardFamilies({ add }: Sinks): void {
    const around = ['\u{1f600}', '\ud83d', '\ude00', '\u{10ffff}', 'é', '́', 'K', '_', '-'];
    for (const sample of [...FORMAT_SAMPLES, ...SCANNER_SAMPLES]) {
        for (const unit of around) {
            add('guard', `${unit}${sample}`);
            add('guard', `${sample}${unit}`);
            add('guard', `${unit}${sample}${unit}`);
        }
    }
}
