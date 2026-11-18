/**
 * golden.test.ts — the rules moved from code into the spec without changing a byte of
 * output. `spec/corpus/golden-b12879a.json.gz` holds what the unchanged package (commit
 * b12879a) returned for the seeded corpus (`tools/corpus`: fuzz families, every vector input,
 * the JS whitespace set, case-fold and astral characters, lone surrogates, adversarial prefixes
 * before every rule, integer-like keys, key collisions, cases crossing every cap) on all four
 * entry points, and for the behaviour probes (`last4`, `detect`, `onEvent`, failures, values
 * that are not JSON, exported constants and helpers). Current output and hits must equal it, with ONE
 * enumerated exception: the AWS secret access key, which the full tier now reports over the whole secret
 * (SPEC 4.17, decided by Lutz 2026-11-18) where secretlint reported from the key name; the recorded output of
 * that case redacted the whole text because the old range covered the key name. And ONE enumerated family: an
 * object key that is itself a full-tier secret (an npm, SendGrid, Shopify, database URL, ... token) is now
 * replaced in the async path, which scans keys with the full rules (SPEC 9.4, Lutz L-N, 2026-11-18); the
 * values, the sync side and every other key are unchanged.
 */
import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { runBehaviors } from '../../tools/corpus/behaviors.ts';
import { replayCase } from '../../tools/corpus/replay.ts';
import type { GoldenFile } from '../../tools/corpus/types.ts';
import * as api from './index.js';

const GOLDEN_PATH = join(import.meta.dir, '..', '..', 'spec', 'corpus', 'golden-b12879a.json.gz');
const GOLDEN = JSON.parse(gunzipSync(readFileSync(GOLDEN_PATH)).toString('utf8')) as GoldenFile;

test('the corpus holds at least 5000 cases', () => {
    expect(GOLDEN.cases.length).toBe(GOLDEN.count);
    expect(GOLDEN.count).toBeGreaterThanOrEqual(5000);
});

/** The cases whose async result changed because of the AWS correction, with the result they give now. */
const AWS_CORRECTION = {
    'vector-109': {
        input: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY9xxx1',
        recordedOut: '[REDACTED:aws]',
        out: 'AWS_SECRET_ACCESS_KEY=[REDACTED:aws]',
        hits: [['@secretlint/secretlint-rule-aws', 22, 62]],
    },
};

/** The cases whose async result changed because an object key is a full-tier secret (L-N). */
const KEY_CASES = [
    'sample-29',
    'sample-41',
    'sample-44',
    'sample-47',
    'sample-50',
    'sample-68',
    'sample-119',
    'sample-122',
    'sample-125',
    'sample-128',
    'sample-131',
    'sample-137',
    'sample-140',
    'fuzz-key-39',
    'fuzz-key-57',
    'fuzz-key-82',
    'fuzz-key-127',
    'fuzz-key-167',
    'fuzz-key-189',
    'fuzz-key-193',
    'fuzz-key-198',
    'fuzz-key-201',
    'fuzz-key-211',
    'fuzz-key-214',
    'fuzz-key-236',
    'fuzz-key-266',
    'fuzz-key-274',
    'fuzz-key-280',
    'fuzz-key-284',
];

/** The value with every object key replaced by its position: what is left when only keys differ. */
function withoutKeys(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(withoutKeys);
    if (value === null || typeof value !== 'object') return value;
    return Object.values(value).map(withoutKeys);
}

test('every corpus case gives the recorded output and hits, but the AWS correction and the keys', async () => {
    const differing: string[] = [];
    for (const item of GOLDEN.cases) {
        const now = await replayCase(api as never, item);
        const same =
            JSON.stringify(now.sync) === JSON.stringify(item.sync) &&
            JSON.stringify(now.async) === JSON.stringify(item.async);
        if (same) continue;
        differing.push(item.id);
        if (KEY_CASES.includes(item.id)) {
            expect(typeof item.input).toBe('object');
            expect(JSON.stringify(now.sync)).toBe(JSON.stringify(item.sync));
            const recorded = item.async.out;
            expect(JSON.stringify(withoutKeys((now.async as { out: unknown }).out))).toBe(
                JSON.stringify(withoutKeys(recorded)),
            );
            expect(JSON.stringify(now.async)).not.toBe(JSON.stringify(item.async));
            continue;
        }
        const expected = AWS_CORRECTION[item.id as keyof typeof AWS_CORRECTION];
        expect(item.input).toBe(expected?.input);
        expect(item.async.out).toBe(expected?.recordedOut);
        expect(JSON.stringify(now.sync)).toBe(JSON.stringify(item.sync));
        expect(now.async as unknown).toEqual({ out: expected?.out, hits: expected?.hits });
    }
    expect(differing).toEqual([...Object.keys(AWS_CORRECTION), ...KEY_CASES]);
}, 120_000);

/** Where two recorded values differ: path, then the recorded and the current leaf. */
function differences(recorded: unknown, now: unknown, path = ''): Array<[string, unknown, unknown]> {
    if (JSON.stringify(recorded) === JSON.stringify(now)) return [];
    const isContainer = (value: unknown): value is Record<string, unknown> =>
        value !== null && typeof value === 'object';
    if (!isContainer(recorded) || !isContainer(now)) return [[path, recorded, now]];
    const keys = new Set([...Object.keys(recorded), ...Object.keys(now)]);
    return [...keys].flatMap((key) => differences(recorded[key], now[key], `${path}.${key}`));
}

test('every behaviour probe gives the recorded result, but the AWS correction in two probes', async () => {
    const now = (await runBehaviors(api as never)) as Record<string, unknown>;
    const differing = Object.keys(GOLDEN.behaviors).filter((name) => {
        return JSON.stringify(now[name]) !== JSON.stringify(GOLDEN.behaviors[name]);
    });
    expect(differing).toEqual(['last4Text', 'detectSecretsDirect']);
    // The secret access key of the probe text: the hit now starts at the secret (22), not at the key name (0), so
    // the text keeps `AWS_SECRET_ACCESS_KEY=`; the same three texts of `last4Text` (last4 on, off, default).
    expect(
        differences(GOLDEN.behaviors.last4Text, now.last4Text).map(([, recorded, current]) => [
            recorded,
            current,
        ]),
    ).toEqual([
        ['[REDACTED:aws:EKEz]', 'AWS_SECRET_ACCESS_KEY=[REDACTED:aws:EKEz]'],
        [0, 22],
        ['[REDACTED:aws]', 'AWS_SECRET_ACCESS_KEY=[REDACTED:aws]'],
        [0, 22],
        ['[REDACTED:aws]', 'AWS_SECRET_ACCESS_KEY=[REDACTED:aws]'],
        [0, 22],
    ]);
    expect(
        differences(GOLDEN.behaviors.detectSecretsDirect, now.detectSecretsDirect).map(
            ([, recorded, current]) => [recorded, current],
        ),
    ).toEqual([[378, 400]]);
    expect(Object.keys(now).sort()).toEqual(Object.keys(GOLDEN.behaviors).sort());
}, 60_000);
