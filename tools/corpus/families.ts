/** The generator families. Each pushes cases through `add`; all randomness comes from the seeded rng. */
import { BASE62, chars, pick, type Rng } from './rng.ts';
import { FORMAT_SAMPLES, SCANNER_SAMPLES } from './samples.ts';
import type { CaseOpts, GenSpec } from './types.ts';

export type Add = (family: string, input: unknown, opts?: CaseOpts) => void;
export type AddGen = (family: string, gen: GenSpec, opts?: CaseOpts) => void;
export type Sinks = { add: Add; addGen: AddGen };

export const WORDS = [
    'the', 'deploy', 'failed', 'user', 'login', 'ok', 'retry', 'secretary', 'passwordless', 'tokenizer',
    'Token', 'expired', 'Basic', 'information', 'bearer', 'auth', 'key', 'id', 'status', 'name', 'value',
    'https://example.test/path?page=2&sort=asc', 'a-b-c', 'x_y_z', 'ünïcödé', '日本語', '😀',
    '{}', '[]', '[REDACTED]', '[REDACTED:key-context]', '[REDACTED:generic-keyword:4dor]', '"', "'",
    '\\', '\n', ':', '=', ',', 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB',
    '3fa85f64-5717-4562-b3fc-2c963f66afa6',
];
const SEPARATORS = [' ', ' ', '\n', ', ', '; ', '\t', ' | '] as const;

export const SECRET_KEYS = [
    'password', 'apiKey', 'api_key', 'client_secret', 'x-auth-token', 'Authorization', 'Set-Cookie',
    'accessToken', 'refresh_token', 'privateKey', 'DB_PASSWORD', 'sessionToken', 'secret', 'token',
    'cookie', 'passphrase', 'pin', 'pwd', 'max_tokens', 'prompt_tokens', 'cardNumber', 'APIKey',
    'userpassword',
    'tokens', 'secretary', 'tokenizer', 'passwordless', 'sid', 'code', 'otp', 'auth', 'pass', 'signature',
];
export const NEUTRAL_KEYS = [
    'name', 'url', 'prompt', 'items', 'body', 'headers', 'status', 'note', 'type', 'id', '__proto__',
    'constructor',
];

export const CONTEXTS: ReadonlyArray<(m: string) => string> = [
    (m) => `password=${m}`, (m) => `password: ${m}`, (m) => `password="${m}"`,
    (m) => `api_key=${m},next=2`, (m) => `{"client_secret":"${m}","ok":true}`,
    (m) => `session_token: ${m}`, (m) => `Authorization: Bearer ${m}`,
    (m) => `Authorization: Basic ${m}`, (m) => `Authorization: Token ${m}`,
    (m) => `https://example.test/cb?token=${m}&x=1`, (m) => `https://example.test/v1?x=1&sig=${m}`,
    (m) => `AWS_SECRET_ACCESS_KEY=${m}`, (m) => `{"access_token": "${m}"}`,
    (m) => `{\\"password\\":\\"${m}\\",\\"ok\\":1}`,
    (m) => `{\\\\\\"client_secret\\\\\\":\\\\\\"${m}\\\\\\"}`,
    (m) => `postgres://user:${m}@db.example.test:5432/app`,
    (m) => `https://x.test/cb?redirect=https://y.test/?token=${m}&z=1`,
    (m) => `https://x.test/cb?redirect=https%3A%2F%2Fy.test%2F%3Ftoken%3D${m}&z=1`,
    (m) => `Cookie: sid=${m}; theme=dark`, (m) => `key dr_sk_${m} used`,
    (m) => `clientSecret: ${m}`, (m) => `secret='${m} with spaces'`, (m) => `credentials=${m}`,
    (m) => `private-key = ${m}`, (m) => `bearer:${m}`, (m) => `token=${m}&token=${m}`,
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
        () => pick(rng, WORDS), () => Math.floor(rng() * 1e6), () => rng() < 0.5, () => null, () => '',
        () => join(rng, noise(rng, 3)), () => Math.floor(rng() * 1e6) / 100, () => 1e21, () => -7,
    ];
    return pick(rng, makers)();
}

function setKey(target: Record<string, unknown>, key: string, value: unknown): void {
    Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

function records(rng: Rng): unknown[] {
    const length = 1 + Math.floor(rng() * 4);
    return Array.from({ length }, (_, n) => ({
        id: `rec-${n}`, url: `https://h${n}.example.test/hook`, token: marker(rng), note: `n${n}`,
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
    '\t', '\n', '\v', '\f', '\r', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    '　', '﻿', '᠎', '\u0085', '​',
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
    '', 'a', '_', '-', '0', 'Z', '😀', '\ud800', '\udc00', 'AIza', 'xai-', 'eyJ', 'ghp_', 'sk-', 'sk-ant-',
    ':', '"', '=', ' ', ' ', '﻿', 'Bearer ', 'password=', 'token: ', '?', '&', '/', '@', '\\',
    '[REDACTED:x]', 'ab.', 'x-', 'srt1.', 'dr_sk_',
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
    addGen('large', { parts: [['lorem ipsum ', 8000], [secret, 1], [' tail ', 3]] });
    addGen('large-window', { parts: [['abcdefghi ', 8976], [' ', 0], [jwt, 1], ['xyz ', 4]] });
    addGen('large-window', { parts: [['abcdefghi ', 9975], [`${SCANNER_SAMPLES[0]}`, 1], [' z', 1]] });
    addGen('large-window', { parts: [['abcdefghi ', 8970], [`${SCANNER_SAMPLES[1]}`, 1], [' z', 1]] });
    addGen('large-window', { parts: [['ab ', 33300], [`${SCANNER_SAMPLES[3]}`, 1], [' z', 1]] });
    addGen('large-pem', { parts: [['-----BEGIN PRIVATE KEY-----', 1], ['ab cd ', 20000]] });
    addGen('large-cap', { parts: [['ab ', 666700], [`${SCANNER_SAMPLES[0]}`, 1], [' ', 1], [secret, 1]] });
    const npm = `${SCANNER_SAMPLES[0]}`;
    addGen('large-cap', { parts: [['ab ', 666663], [' ', 1], [npm, 1], [' ', 1], [secret, 1]] });
    addGen('large-default-cap', { parts: [['ab ', 1333334], [secret, 1]] });
}
