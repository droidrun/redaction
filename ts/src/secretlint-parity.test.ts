/**
 * secretlint-parity.test.ts — the full tier equals the secretlint 13.0.4 preset it was ported from: the same
 * (rule id, range) pairs in both directions on the parity corpus, with ONE documented deviation, the range of
 * the AWS secret access key (SPEC 4.17: the whole secret, not `[match start, match start + 40]`).
 *
 * The corpus: the upstream 13.0.4 rule fixtures (`spec/corpus/secretlint-13.0.4`), every string of the golden
 * corpus (the fuzz families and vectors of the package), hand-written filter-branch cases of every rule, and
 * seeded near-misses (`secretlint-fuzz.fixture.ts`; `PARITY_FUZZ=<count>` runs more of them).
 */
import { describe, expect, test } from 'bun:test';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import type { GoldenFile } from '../../tools/corpus/types.ts';
import { expandGen } from '../../tools/corpus/types.ts';
import { isLetter } from './algorithms/letters.js';
import { detectFullHits } from './full-rules.js';
import { oracleHits, withAwsCorrection } from './secretlint-oracle.fixture.ts';
import { nearMisses } from './secretlint-fuzz.fixture.ts';

const SPEC_DIR = join(import.meta.dir, '..', '..', 'spec');
const FIXTURES = join(SPEC_DIR, 'corpus', 'secretlint-13.0.4');
const GOLDEN = join(SPEC_DIR, 'corpus', 'golden-b12879a.json.gz');
const MAX_GOLDEN_STRING = 20_000;
const FUZZ_COUNT = Number(process.env.PARITY_FUZZ ?? 20000);
const NOT_INPUT = new Set(['output.json', 'options.ts', '.secretlintrc.json', 'README.md']);
const RULE_INPUTS = new Set(['input', 'input.txt', 'input.json']);

type Case = { name: string; text: string };

function filesBelow(dir: string): string[] {
    return readdirSync(dir).flatMap((entry) => {
        const path = join(dir, entry);
        return statSync(path).isDirectory() ? filesBelow(path) : [path];
    });
}

function fixtureCases(): Case[] {
    return filesBelow(FIXTURES)
        .filter((path) => !NOT_INPUT.has(path.split('/').pop() as string))
        .map((path) => ({ name: path.slice(FIXTURES.length + 1), text: readFileSync(path, 'utf8') }));
}

function strings(value: unknown, out: Set<string>): void {
    if (typeof value === 'string') out.add(value);
    else if (Array.isArray(value)) value.forEach((item) => strings(item, out));
    else if (value !== null && typeof value === 'object') {
        for (const [key, item] of Object.entries(value)) {
            out.add(key);
            strings(item, out);
        }
    }
}

function goldenCases(): Case[] {
    const file = JSON.parse(gunzipSync(readFileSync(GOLDEN)).toString('utf8')) as GoldenFile;
    const found = new Set<string>();
    for (const item of file.cases) strings(item.gen === undefined ? item.input : expandGen(item.gen), found);
    return [...found]
        .filter((text) => text.length <= MAX_GOLDEN_STRING)
        .map((text, index) => ({
            name: `golden ${index}`,
            text,
        }));
}

const word = (char: string, count: number): string => char.repeat(count);
const AWS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETSKEY';
const PEM_BODY = `MI${word('A', 150)}`;
const HAND_WRITTEN: Case[] = [
    // letter guard: a letter in front refuses, any other unit does not (BMP, astral, lone surrogate)
    ...['é', 'Ω', '漢', '\u{1d400}', ' ', '1', '_', '\u{1f600}', '\ud800', '\udc00', '﻿'].map((front) => ({
        name: `letter guard ${JSON.stringify(front)}`,
        text: `${front}ghp_${word('a', 36)}`,
    })),
    { name: 'BOM first', text: `﻿ghp_${word('a', 36)}` },
    { name: 'github 37 units', text: `ghp_${word('a', 37)}` },
    { name: 'github 35 units', text: `ghp_${word('a', 35)}` },
    { name: 'github then dash', text: `ghp_${word('a', 36)}-` },
    { name: 'github app token', text: `ghs_123_${word('a', 5)}.${word('b', 7)}.${word('c', 9)}` },
    { name: 'github app 21 digits', text: `ghs_${word('1', 21)}_a.b.c` },
    { name: 'github classic and app overlap', text: `ghs_1_${word('a', 34)}.b.c` },
    { name: 'sendgrid 69', text: `SG.${word('a', 22)}.${word('b', 43)}` },
    { name: 'sendgrid 69 with dash', text: `SG.${word('a', 22)}.${word('b', 20)}-${word('c', 22)}` },
    { name: 'sendgrid 70', text: `SG.${word('a', 22)}.${word('b', 44)}` },
    { name: 'sendgrid start inside', text: `SG.xxSG.${word('a', 30)}.${word('b', 30)}` },
    { name: 'slack chain', text: 'xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx' },
    { name: 'slack underscore end', text: 'xoxb-111-222-abc_' },
    { name: 'slack digit option', text: 'xoxa-2-111-abc' },
    { name: 'slack webhook', text: 'HTTPS://Hooks.Slack.Com/Services/Tabc/Bdef/ghi' },
    { name: 'privatekey ok', text: `-----BEGIN PRIVATE KEY-----\n${PEM_BODY}\n-----END PRIVATE KEY-----` },
    {
        name: 'privatekey escaped newlines',
        text: `-----BEGIN RSA PRIVATE KEY-----\\n${PEM_BODY}\\n-----END RSA PRIVATE KEY-----`,
    },
    {
        name: 'privatekey placeholder',
        text: `-----BEGIN PRIVATE KEY-----\n${word('x', 150)}\n-----END PRIVATE KEY-----`,
    },
    { name: 'privatekey no footer', text: `-----BEGIN PRIVATE KEY-----\n${PEM_BODY}` },
    {
        name: 'privatekey header twice',
        text: `-----BEGIN PRIVATE KEY-----BEGIN PRIVATE KEY-----\n${PEM_BODY}\n-----END PRIVATE KEY-----`,
    },
    {
        name: 'privatekey short body',
        text: `-----BEGIN PRIVATE KEY-----\nMI${word('A', 90)}\n-----END PRIVATE KEY-----`,
    },
    {
        name: 'privatekey openssh',
        text: `-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE${word('A', 100)}\n-----END OPENSSH PRIVATE KEY-----`,
    },
    { name: 'basicauth', text: 'https://alice:hunter2x@host.example.com/path' },
    { name: 'basicauth placeholder password', text: 'https://alice:password@host.example.com' },
    { name: 'basicauth repeated', text: 'https://alice:aaaa@host.example.com' },
    { name: 'basicauth short user', text: 'https://a:hunter2x@host.example.com' },
    { name: 'basicauth ftps', text: 'ftps://alice:Zx9kQ7m@a.b' },
    { name: 'postgres', text: 'postgres://admin:hunter2secret@db.example.com:5432/app?ssl=true' },
    { name: 'postgres template password', text: 'postgres://admin:${DB_PASS}@db/app' },
    { name: 'postgres same user and password', text: 'postgres://admin:admin@db/app' },
    { name: 'postgres placeholder', text: 'postgres://admin:Password@db/app' },
    { name: 'mongodb srv', text: 'MongoDB+SRV://bob:Zx9!kQ7m@cluster0.mongodb.net/test' },
    { name: 'jdbc mysql', text: 'jdbc:mysql://bob:Zx9!kQ7m@localhost:3306/db' },
    { name: 'no credentials', text: 'postgres://db.example.com:5432/app' },
    { name: 'aws key id', text: 'creds AKIAQR7ZKT4MW2PLX9BD end' },
    { name: 'aws key id example', text: 'AKIAIOSFODNN7EXAMPLE' },
    { name: 'aws account id', text: '"aws_account_id": "1234-5678-9012"' },
    { name: 'aws secret quoted', text: `"aws_secret_access_key": "${AWS_KEY}"` },
    { name: 'aws secret example', text: 'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' },
    { name: 'openai legacy', text: `sk-${word('a', 20)}T3BlbkFJ${word('b', 20)}` },
    { name: 'openai project', text: `sk-proj-${word('a', 74)}T3BlbkFJ${word('b', 58)}` },
    { name: 'anthropic', text: `sk-ant-api03-${word('A', 93)}AA` },
    { name: 'anthropic no tail', text: `sk-ant-api03-${word('A', 93)}AB` },
    { name: 'grafana cloud padding', text: `glc_${word('A', 40)}==` },
    { name: 'grafana cloud 3 padding', text: `glc_${word('A', 40)}===` },
    { name: 'databricks dash digit', text: `dapi${word('a', 32)}-1` },
    { name: 'databricks dash digit then hex', text: `dapi${word('a', 32)}-1a` },
    { name: 'tailscale', text: `tskey-auth-${word('a', 12)}-${word('b', 30)}` },
    { name: 'cloudflare', text: `cfut_${word('A', 40)}${word('a', 8)}` },
    { name: 'AWS correction', text: `AWS_SECRET_ACCESS_KEY = ${AWS_KEY}\n` },
];

function fuzzCases(): Case[] {
    return nearMisses(20251118, FUZZ_COUNT).map((text, index) => ({ name: `near miss ${index}`, text }));
}

const ALL_CASES: Case[] = [...fixtureCases(), ...HAND_WRITTEN, ...goldenCases(), ...fuzzCases()];

function pairs(hits: Array<[string, number, number]>): string[] {
    return [...new Set(hits.map(([ruleId, start, end]) => `${ruleId} ${start}-${end}`))].sort();
}

async function compare(text: string): Promise<{ expected: string[]; actual: string[] }> {
    const expected = pairs(withAwsCorrection(await oracleHits(text), text));
    const actual = pairs(detectFullHits(text).map((hit) => [hit.ruleId, hit.range[0], hit.range[1]]));
    return { expected, actual };
}

describe('the full tier equals the secretlint 13.0.4 preset', () => {
    test('the parity corpus is large and covers every ported rule', () => {
        expect(ALL_CASES.length).toBeGreaterThan(10_000);
        expect(fixtureCases().length).toBeGreaterThanOrEqual(90);
    });

    test('same (rule id, range) pairs in both directions on every case', async () => {
        const differing: string[] = [];
        let hits = 0;
        for (const item of ALL_CASES) {
            const { expected, actual } = await compare(item.text);
            hits += expected.length;
            if (JSON.stringify(expected) !== JSON.stringify(actual)) {
                const shown = JSON.stringify(item.text.slice(0, 120));
                differing.push(
                    `${item.name} ${shown}: expected ${expected.join('|')} actual ${actual.join('|')}`,
                );
            }
        }
        expect(differing.slice(0, 10).map((line) => line.slice(0, 600))).toEqual([]);
        expect(hits).toBeGreaterThan(1500);
    }, 900_000);

    test('every rule of the preset but gcp and filter-comments reports on the corpus', async () => {
        const seen = new Set<string>();
        for (const item of ALL_CASES.slice(0, 4000)) {
            for (const hit of await oracleHits(item.text)) seen.add(hit.ruleId);
        }
        expect([...seen].sort()).toEqual([
            '1password',
            'anthropic',
            'aws',
            'basicauth',
            'cloudflare',
            'database-connection-string',
            'databricks',
            'docker',
            'figma',
            'github',
            'gitlab',
            'grafana',
            'groq',
            'hashicorp-vault',
            'huggingface',
            'linear',
            'notion',
            'npm',
            'openai',
            'privatekey',
            'sendgrid',
            'shopify',
            'slack',
            'stripe',
            'tailscale',
            'vercel',
        ]);
    }, 300_000);

    test('the AWS secret access key: the preset reports from the key name, the full tier the secret', async () => {
        const text = `AWS_SECRET_ACCESS_KEY = ${AWS_KEY}\n`;
        expect((await oracleHits(text)).map((hit) => hit.range)).toEqual([[0, 40]]);
        expect(detectFullHits(text)).toEqual([{ ruleId: 'aws', range: [24, 64] }]);
    });
});

describe('the harness reproduces the upstream expectations', () => {
    type Recorded = { messages: Array<{ messageId: string; range: [number, number] }> };
    const ruleDirs = readdirSync(FIXTURES).filter((entry) => statSync(join(FIXTURES, entry)).isDirectory());
    const cases = ruleDirs.flatMap((rule) =>
        readdirSync(join(FIXTURES, rule)).flatMap((name) => {
            const dir = join(FIXTURES, rule, name);
            const files = readdirSync(dir);
            const input = files.find((file) => RULE_INPUTS.has(file));
            const hasOptions = files.includes('options.ts') || files.includes('.secretlintrc.json');
            const isPlain = input !== undefined && !hasOptions;
            return isPlain
                ? [[`${rule}/${name}`, rule, join(dir, input), join(dir, 'output.json')] as const]
                : [];
        }),
    );

    test.each(cases)('%s', async (_name, rule, inputPath, outputPath) => {
        const text = readFileSync(inputPath, 'utf8');
        const recorded = JSON.parse(readFileSync(outputPath, 'utf8')) as Recorded;
        const actual = (await oracleHits(text)).filter((hit) => hit.ruleId === rule);
        const key = (item: { messageId: string; range: [number, number] }): string =>
            `${item.messageId} ${item.range[0]}-${item.range[1]}`;
        expect(actual.map(key).sort()).toEqual(recorded.messages.map(key).sort());
    });
});

describe('the letter table (SPEC 5.6)', () => {
    const LAST_CODE_POINT = 0x10ffff;

    test('every letter of the Unicode 15.0.0 table is a letter of this Node, and the guard never uses Node', () => {
        const letters = /^\p{L}$/u;
        const notLetters: number[] = [];
        for (let codePoint = 0; codePoint <= LAST_CODE_POINT; codePoint++) {
            const isSurrogate = codePoint >= 0xd800 && codePoint <= 0xdfff;
            if (isLetter(codePoint) && (isSurrogate || !letters.test(String.fromCodePoint(codePoint)))) {
                notLetters.push(codePoint);
            }
        }
        expect(notLetters).toEqual([]);
    });

    test('script boundaries', () => {
        const letters = [
            0x41, 0x5a, 0xaa, 0xb5, 0xba, 0xc0, 0xd6, 0xf8, 0x2c1, 0x370, 0x3ff, 0x4e00, 0x9fff, 0xac00,
            0xd7a3, 0x1d400, 0x1d7cb, 0x20000, 0x2a6df, 0x2ebe0,
        ];
        const others = [
            0x40, 0x5b, 0x60, 0x7b, 0xa9, 0xab, 0xd7, 0xf7, 0x2c2, 0x30, 0x39, 0xd7a4, 0xd800, 0xdfff,
            0x1d7ce, 0x1f600,
        ];
        expect(letters.filter((codePoint) => !isLetter(codePoint))).toEqual([]);
        expect(others.filter((codePoint) => isLetter(codePoint))).toEqual([]);
        expect(existsSync(FIXTURES)).toBe(true);
    });
});
