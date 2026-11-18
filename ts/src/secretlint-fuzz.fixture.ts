/**
 * Near-miss generator of the parity test: seeded strings built around the bounds and boundaries of every
 * ported rule (one unit short or long, a letter or a separator in front, a word unit behind, repeated
 * prefixes), so the interpreter and the upstream rules are compared exactly where they could differ.
 */
import { BASE62, chars, mulberry32, pick, type Rng } from '../../tools/corpus/rng.ts';

const ANU = `${BASE62}_`;
const ANUD = `${BASE62}_-`;
const B64 = `${BASE62}+/`;
const HEX = '0123456789abcdefABCDEF';
const DIGITS = '0123456789';
// Letters (and non-letters) every Unicode version since 15.0 agrees on.
const BEFORE = [
    '',
    '',
    '',
    ' ',
    'a',
    'Z',
    'é',
    'Ω',
    '漢',
    'ʰ',
    'ǅ',
    'ª',
    '\u{1d400}',
    '\u{1f600}',
    '\ud800',
    '\udc00',
    '1',
    '_',
    '-',
    '"',
    '.',
    '\n',
    ' ',
    '﻿',
    '²',
    '٣',
];
const AFTER = ['', '', ' ', 'a', 'Z', '0', '_', '-', '.', '=', '/', '+', '\n', '"', 'é', '\u{1d400}', ' '];

const near = (rng: Rng, min: number, max: number): number => {
    const candidates = [
        min - 1,
        min,
        min + 1,
        max - 1,
        max,
        max + 1,
        min + Math.floor(rng() * (max - min + 1)),
    ];
    return Math.max(0, pick(rng, candidates));
};
const run = (rng: Rng, alphabet: string, min: number, max: number): string =>
    chars(rng, alphabet, near(rng, min, max));
const surround = (rng: Rng, core: string): string => `${pick(rng, BEFORE)}${core}${pick(rng, AFTER)}`;

type Family = (rng: Rng) => string;

const token =
    (prefixes: string[], alphabet: string, min: number, max: number, tail = ''): Family =>
    (rng) =>
        surround(rng, `${pick(rng, prefixes)}${run(rng, alphabet, min, max)}${tail}`);

function base64Of(text: string): string {
    return Buffer.from(text, 'latin1').toString('base64');
}

function onePassword(rng: Rng): string {
    const inner = pick(rng, [
        () => `{"a":"${chars(rng, BASE62, 80 + Math.floor(rng() * 60))}"}`,
        () => `["${chars(rng, BASE62, 90 + Math.floor(rng() * 40))}"]`,
        () => `{"a":"${chars(rng, BASE62, 100)}",}`,
        () => `"${chars(rng, BASE62, 110)}"`,
        () => `null${' '.repeat(100)}`,
        () => `{"k":[1,2.5e3,-0,true,false,null,{"x":"${chars(rng, BASE62, 90)}"}]}`,
        () => `{"k":01,"p":"${chars(rng, BASE62, 100)}"}`,
        () => `{"k":"\\u00e9\\ud800","p":"${chars(rng, BASE62, 100)}"}`,
        () => `{"a":"${chars(rng, BASE62, 100)}"} x`,
        () => `{}${' '.repeat(110)}`,
        () =>
            `{"a":"${chars(rng, BASE62, Math.max(1, Math.floor(((near(rng, 100, 1280) + 5) * 3) / 4) - 8 + Math.floor(rng() * 4)))}"}`,
        () =>
            `{"a":"${chars(rng, BASE62, Math.max(1, Math.floor(((near(rng, 100, 1280) + 5) * 3) / 4) - 8 + Math.floor(rng() * 4)))}"}`,
    ])();
    let encoded = base64Of(inner);
    const mutation = Math.floor(rng() * 8);
    if (mutation === 0) encoded = encoded.replace(/=+$/, '');
    if (mutation === 1) encoded = `${encoded.slice(0, 50)}=${encoded.slice(50)}`;
    if (mutation === 2) encoded = `${encoded.slice(0, 50)}A${encoded.slice(50)}`;
    if (mutation === 3) encoded = encoded.replace(/fQ(=*)$/, 'fq$1');
    if (mutation === 4) encoded += '=';
    return surround(rng, `ops_${encoded}`);
}

function sendgrid(rng: Rng): string {
    const exact = rng() < 0.5;
    const a = exact ? 1 + Math.floor(rng() * 40) : near(rng, 1, 128);
    const tail = exact ? 66 - a - 1 : near(rng, 1, 260);
    const shape = Math.floor(rng() * 4);
    const first = chars(rng, ANU, a);
    let body = chars(rng, ANU, Math.max(1, tail));
    if (shape === 1 && tail > 2) {
        const split = 1 + Math.floor(rng() * (tail - 1));
        body = `${chars(rng, ANU, split)}${pick(rng, ['-', '_'])}${chars(rng, ANU, Math.max(1, tail - split - 1))}`;
    }
    if (shape === 2) body = `${chars(rng, ANU, near(rng, 1, 128))}-${chars(rng, ANU, near(rng, 1, 128))}`;
    if (shape === 3)
        body = `${chars(rng, ANU, 128)}${pick(rng, ['_', 'a'])}${chars(rng, ANU, near(rng, 100, 130))}`;
    return surround(rng, `SG.${first}.${body}`);
}

function slack(rng: Rng): string {
    const lead = pick(rng, ['xoxb', 'xoxp', 'xapp', 'xoxa', 'xoxo', 'xoxr', 'xoxs']);
    const segments = 1 + Math.floor(rng() * 5);
    let out = `${lead}-`;
    if (rng() < 0.3) out += `${pick(rng, [...DIGITS])}-`;
    for (let i = 0; i < segments; i++) {
        out += `${run(rng, BASE62, 1, 40)}${i < segments - 1 ? pick(rng, ['-', '-', '-', '--', '_']) : ''}`;
    }
    return surround(rng, out);
}

function pem(rng: Rng): string {
    const kind = pick(rng, ['', 'RSA ', 'DSA ', 'EC ', 'OPENSSH ', 'PGP ', 'XX ']);
    const block = pick(rng, ['', ' BLOCK']);
    const space = pick(rng, [' ', '']);
    const magic = pick(rng, ['MI', 'MI', 'b3BlbnNzaC1rZXktdjE', 'XX']);
    const size = pick(rng, [98, 99, 100, 101, 102, 150, 300, 9998, 9999, 10000, 10001, 10002, 10003]);
    let body = magic + chars(rng, B64, Math.max(0, size - magic.length));
    if (rng() < 0.3) body = body.replace(/(.{64})/g, '$1\n');
    if (rng() < 0.15) body = body.replace(/(.{64})/g, '$1\\n');
    if (rng() < 0.15) body += pick(rng, ['=', '==', '=x', ' ', '\r\n', '...']);
    if (rng() < 0.1) body = `${body.slice(0, 40)}${pick(rng, ['*', '.', '-', 'é', '\\r'])}${body.slice(40)}`;
    const lead = pick(rng, ['', '\n', '\n', ' ']);
    const trail = pick(rng, ['', '\n', '\n', '\n\n']);
    const footerKind = rng() < 0.9 ? kind : 'RSA ';
    const header = `-----BEGIN${space}${kind}PRIVATE KEY${block}-----`;
    const footer = `-----END${space}${footerKind}PRIVATE KEY${block}-----`;
    return surround(rng, `${header}${lead}${body}${trail}${footer}`);
}

const SCHEMES = [
    'postgres',
    'postgresql',
    'POSTGRES',
    'mongodb',
    'mongodb+srv',
    'MongoDB',
    'mysql',
    'mysqlx',
    'jdbc:mysql',
    'JDBC:MYSQL',
    'https',
    'http',
    'ftp',
    'ftps',
];
const NAMES = ['admin', 'user', 'root', 'alice', 'bob', 'a', 'x:y', '$USER', 'u'.repeat(101), 'SOMEONE'];
const PASSWORDS = [
    'hunter2',
    'pass',
    'password',
    'PASSWORD',
    'secret',
    'aaaa',
    'aaaaa',
    'abab',
    '1111',
    '${DB_PASS}',
    '{{p}}',
    '{pw}',
    '%PW%',
    '$PW',
    '$(pw)',
    'p@ss',
    'pa{ss}wo',
    'a'.repeat(201),
    'Zx9!kQ7m',
    'xyz',
    'abcd',
    'localhost',
    'Example.COM',
    '$',
    '${',
    '{}',
    '{x}y',
    'a$B',
    '$a',
    'root',
    'ROOT',
    'YOUR_PASSWORD',
    'your_password',
    '{password}',
    '$(a)',
];
const HOSTS = [
    'db.example.com',
    'localhost:5432',
    'h',
    'a-b.co',
    'x.y(z)',
    'host.com',
    'h.verylongtld',
    'a.b',
    '127.0.0.1',
];

function database(rng: Rng): string {
    const scheme = pick(rng, SCHEMES);
    const user = pick(rng, NAMES);
    const password = rng() < 0.15 ? user : pick(rng, PASSWORDS);
    const credentials = rng() < 0.85 ? `${user}:${password}@` : '';
    const tail = `${pick(rng, ['', '/db', '/db?x=1', '?ssl=true', '/', '/' + 'd'.repeat(101)])}${pick(rng, ['', ' ', '\n', '"'])}`;
    return surround(rng, `${scheme}://${credentials}${pick(rng, HOSTS)}${tail}`);
}

function aws(rng: Rng): string {
    const quote = () => pick(rng, ['', '"', "'"]);
    const key = pick(rng, ['AKIA', 'ASIA', 'A3T0', 'AGPA', 'AIDA', 'AROA', 'AIPA', 'ANPA', 'ANVA', 'AXXX']);
    const kind = Math.floor(rng() * 3);
    if (kind === 0) {
        return surround(rng, `${key}${run(rng, '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', 16, 16)}`);
    }
    const sep = `${pick(rng, ['', ' ', ' ', '\t'])}${pick(rng, [':', '=', '=>'])}${pick(rng, ['', ' ', '\n'])}`;
    if (kind === 1) {
        const prefix = pick(rng, ['', 'aws_', 'AWS_', 'Aws', 'AWS']);
        const number = `${chars(rng, DIGITS, 4)}${pick(rng, ['', '-'])}${chars(rng, DIGITS, 4)}${pick(rng, ['', '-'])}${chars(rng, DIGITS, near(rng, 4, 4))}`;
        const name = `${prefix}${pick(rng, ['account', 'ACCOUNT', 'Account', 'accounT'])}${pick(rng, ['', '_'])}${pick(rng, ['', 'id', 'ID', 'Id'])}`;
        return surround(rng, `${quote()}${name}${quote()}${sep}${quote()}${number}${quote()}`);
    }
    const prefix = pick(rng, ['', 'aws_', 'AWS_', 'Aws', 'AWS']);
    const name = `${prefix}${pick(rng, ['secret', 'SECRET', 'Secret'])}${pick(rng, ['', '_'])}${pick(rng, ['access', 'ACCESS', 'Access'])}${pick(rng, ['', '_'])}${pick(rng, ['key', 'KEY', 'Key'])}`;
    const value =
        rng() < 0.1
            ? 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
            : chars(rng, `${BASE62}/+=`, near(rng, 40, 40));
    return surround(rng, `${quote()}${name}${quote()}${sep}${quote()}${value}${quote()}`);
}

function openai(rng: Rng): string {
    const long = () => chars(rng, ANUD, pick(rng, [74, 58, 73, 75, 57, 59]));
    if (rng() < 0.5) {
        return surround(
            rng,
            `sk-${pick(rng, ['proj', 'svcacct', 'admin', 'user'])}-${long()}T3BlbkFJ${long()}`,
        );
    }
    return surround(
        rng,
        `sk-${chars(rng, BASE62, near(rng, 20, 20))}T3BlbkFJ${chars(rng, BASE62, near(rng, 20, 20))}`,
    );
}

function webhook(rng: Rng): string {
    const scheme = pick(rng, ['https', 'HTTPS', 'Https', 'http']);
    const host = pick(rng, ['hooks.slack.com', 'HOOKS.SLACK.COM', 'hooks.slack.co']);
    const part = (lead: string) =>
        `${pick(rng, [lead, lead.toLowerCase(), lead.toUpperCase(), 'X'])}${run(rng, BASE62, 1, 40)}`;
    return surround(
        rng,
        `${scheme}://${host}/${pick(rng, ['services', 'SERVICES'])}/${part('T')}/${part('B')}/${run(rng, BASE62, 1, 40)}`,
    );
}

function githubApp(rng: Rng): string {
    const seg = (alphabet: string, min: number, max: number) =>
        chars(rng, alphabet, pick(rng, [min - 1, min, max, max + 1, 5, 40]));
    const digits = chars(rng, DIGITS, near(rng, 1, 20));
    return surround(rng, `ghs_${digits}_${seg(ANUD, 1, 1000)}.${seg(ANUD, 1, 10000)}.${seg(ANUD, 1, 1000)}`);
}

function basicAuth(rng: Rng): string {
    const user = pick(rng, [
        'admin',
        'a',
        'ab',
        'myusername',
        'MyUserName2',
        'user-1',
        'LOCALHOST',
        'x_y',
        'u:v',
        'a b',
    ]);
    const password = pick(rng, [
        'hunter2',
        'pass',
        'aaaa',
        'password',
        'MYPASSWORD1',
        'ab12',
        'a'.repeat(257),
        'abcd',
        'Zx9kQ7m',
        '1111',
        'Pa-ss_9',
    ]);
    const host = pick(rng, [
        'example.com',
        'a.b',
        'a.verylongtld',
        'x-y.z9',
        'h.a(b)',
        'localhost',
        '127.0.0.1',
        'a.bc.de',
        'h.com.',
    ]);
    return surround(
        rng,
        `${pick(rng, ['http', 'https', 'ftp', 'ftps', 'sftp'])}://${user}:${password}@${host}${pick(rng, ['', '/p', ' ', '-', '_'])}`,
    );
}

const FAMILIES: Family[] = [
    token(['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'ghx_'], ANU, 36, 36),
    token(['github_pat_'], ANU, 82, 82),
    githubApp,
    token(['shppa_', 'shpca_', 'shpat_', 'shpss_', 'shpxx_'], BASE62, 32, 64),
    token(['sk_live_', 'sk_test_', 'rk_live_', 'rk_test_', 'pk_live_'], BASE62, 24, 99),
    token(['glpat-'], ANUD, 20, 128),
    (rng) => surround(rng, `glc_${run(rng, B64, 32, 400)}${'='.repeat(pick(rng, [0, 1, 2, 3]))}`),
    (rng) => surround(rng, `glsa_${run(rng, BASE62, 32, 32)}_${run(rng, HEX, 8, 8)}`),
    token(['gsk_'], BASE62, 52, 52),
    token(['hf_'], 'abcXYZ', 34, 34),
    token(['lin_api_'], ANU, 32, 128),
    (rng) => surround(rng, `ntn_${run(rng, DIGITS, 11, 11)}${run(rng, BASE62, 35, 35)}`),
    token(['hvs.', 'hvr.'], ANUD, 90, 120),
    token(['hvb.'], ANUD, 138, 300),
    token(['vcp_', 'vci_', 'vca_', 'vcr_', 'vck_', 'vcx_'], BASE62, 20, 60),
    (rng) =>
        surround(rng, `dapi${run(rng, HEX, 32, 32)}${pick(rng, ['', '-1', '-12', '-a', '-', '-1a', '-1-'])}`),
    token(['dckr_pat_'], ANUD, 27, 27),
    token(['figd_'], ANUD, 40, 200),
    (rng) =>
        surround(
            rng,
            `${pick(rng, ['cfk', 'cfut', 'cfat', 'cfx'])}_${run(rng, BASE62, 40, 40)}${run(rng, '0123456789abcdefAF', 8, 8)}`,
        ),
    (rng) =>
        surround(rng, `tskey-${run(rng, 'abcdefz', 2, 20)}-${run(rng, ANU, 8, 40)}-${run(rng, ANU, 16, 60)}`),
    token(['npm_'], ANU, 36, 36),
    (rng) =>
        surround(
            rng,
            `sk-ant-api0${pick(rng, [...DIGITS])}-${run(rng, ANUD, 90, 128)}${pick(rng, ['AA', 'AA', 'A', 'AAA', 'Aa', ''])}`,
        ),
    onePassword,
    sendgrid,
    slack,
    pem,
    database,
    basicAuth,
    aws,
    openai,
    webhook,
];

const GLUE = [
    '',
    ' ',
    '\n',
    ' ghs_1_',
    ' SG.a.',
    ' xoxb-a-',
    '-----BEGIN PRIVATE KEY-----',
    'sk-',
    'postgres://a:bbbb@',
    '"',
    '\\n',
];

/** `count` seeded strings: one family each, or two or three of them glued together. */
export function nearMisses(seed: number, count: number): string[] {
    const rng = mulberry32(seed);
    const out: string[] = [];
    for (let i = 0; i < count; i++) {
        const pieces = rng() < 0.75 ? 1 : 2 + Math.floor(rng() * 2);
        let text = '';
        for (let piece = 0; piece < pieces; piece++) text += pick(rng, GLUE) + pick(rng, FAMILIES)(rng);
        out.push(text);
    }
    return out;
}
