/**
 * golden.test.ts — the rules moved from code into the spec without changing a byte of
 * output. `spec/corpus/golden-b12879a.json.gz` holds what the unchanged package (commit
 * b12879a) returned for the seeded corpus (`tools/corpus`: fuzz families, every vector input,
 * the JS whitespace set, case-fold and astral characters, lone surrogates, adversarial prefixes
 * before every rule, integer-like keys, key collisions, cases crossing every cap) on all four
 * entry points, and for the behaviour probes (`last4`, `detect`, `onEvent`, failures, values
 * that are not JSON, exported constants and helpers). Current output and hits must equal it, with these
 * enumerated exceptions (each list below is literal and each case is checked, not only counted):
 *  - the AWS secret access key, which the full tier now reports over the whole secret (SPEC 4.17, decided 2026-11-18);
 *  - 24 cases whose object key is itself a full-tier secret: the async path scans keys with the full rules and the
 *    key is now its placeholder (SPEC 9.4); 5 more differ only in the hit id of such a key;
 *  - 120 key-collision cases (both tiers): keys that redact to one key keep every value, the later ones are
 *    numbered `#2`, `#3` (SPEC 8); the recorded output lost values.
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

/** Async result changed because an object key is a full-tier secret: the key is now its placeholder. */
const KEY_CASES = [
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

/** Same key, same value; only the hit ids differ (a full-tier hit wins the tie and carries its 0.2.0 id). */
const HIT_ID_CASES = ['sample-29', 'sample-41', 'sample-44', 'sample-47', 'sample-50'];

/** Keys that redact to one key: the numbering rule numbers the later ones, the recorded output lost values. */
const COLLISION_CASES = [
    0, 1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16, 18, 19, 21, 22, 24, 25, 27, 28, 30, 31, 33, 34, 36, 37, 39, 40,
    42, 43, 45, 46, 48, 49, 51, 52, 54, 55, 57, 58, 60, 61, 63, 64, 66, 67, 69, 70, 72, 73, 75, 76, 78, 79,
    81, 82, 84, 85, 87, 88, 90, 91, 93, 94, 96, 97, 99, 100, 102, 103, 105, 106, 108, 109, 111, 112, 114, 115,
    117, 118, 120, 121, 123, 124, 126, 127, 129, 130, 132, 133, 135, 136, 138, 139, 141, 142, 144, 145, 147,
    148, 150, 151, 153, 154, 156, 157, 159, 160, 162, 163, 165, 166, 168, 169, 171, 172, 174, 175, 177, 178,
].map((index) => `key-collision-${index}`);

const RULE_PLACEHOLDER = /^\[REDACTED:[a-z0-9-]+\]$/;
const NUMBER_SUFFIX = /#\d+\]$/;

type Outcome = { out: Record<string, unknown>; hits: Array<[string, number, number]> };

function expectKeyCase(
    item: { input: unknown; sync: Outcome; async: Outcome },
    now: { sync: Outcome; async: Outcome },
): void {
    expect(typeof item.input).toBe('object');
    expect(JSON.stringify(now.sync)).toBe(JSON.stringify(item.sync));
    expect(JSON.stringify(now.async.hits)).not.toBe(JSON.stringify(item.async.hits));
    const changed = collectChangedKeys(item.async.out, now.async.out);
    expect(changed.length).toBeGreaterThan(0);
    for (const [, key] of changed) expect(key).toMatch(RULE_PLACEHOLDER);
}

/** Changed keys anywhere in two nested outputs of one shape (values equal, keys compared by position). */
function collectChangedKeys(recorded: unknown, now: unknown): Array<[string, string]> {
    if (Array.isArray(recorded)) {
        return recorded.flatMap((item, at) => collectChangedKeys(item, (now as unknown[])[at]));
    }
    if (recorded === null || typeof recorded !== 'object') {
        expect(now).toEqual(recorded);
        return [];
    }
    const before = Object.keys(recorded);
    const after = Object.keys(now as object);
    expect(after.length).toBe(before.length);
    return before.flatMap((key, at) => {
        const children = collectChangedKeys(
            (recorded as Record<string, unknown>)[key],
            (now as Record<string, unknown>)[after[at] as string],
        );
        return after[at] === key ? children : [[key, after[at] as string] as [string, string], ...children];
    });
}

/** A collision case: no value is lost now; each numbered key is a recorded key with `#n`. */
function expectCollisionCase(
    item: { input: unknown; sync: Outcome; async: Outcome },
    now: { sync: Outcome; async: Outcome },
): void {
    const inputKeys = Object.keys(item.input as Record<string, unknown>);
    for (const side of ['sync', 'async'] as const) {
        const recordedKeys = Object.keys(item[side].out);
        const nowKeys = Object.keys(now[side].out);
        expect(nowKeys.length).toBe(inputKeys.length);
        const numbered = nowKeys.filter((key) => NUMBER_SUFFIX.test(key));
        expect(numbered.length).toBe(inputKeys.length - recordedKeys.length);
        for (const key of nowKeys) {
            expect(recordedKeys).toContain(key.replace(NUMBER_SUFFIX, ']'));
            expect(now[side].out[key]).toEqual(item[side].out[key.replace(NUMBER_SUFFIX, ']')]);
        }
    }
}

test('every corpus case gives the recorded result, but the AWS correction and the keys', async () => {
    const differing: string[] = [];
    for (const item of GOLDEN.cases) {
        const now = await replayCase(api as never, item);
        const same =
            JSON.stringify(now.sync) === JSON.stringify(item.sync) &&
            JSON.stringify(now.async) === JSON.stringify(item.async);
        if (same) continue;
        differing.push(item.id);
        const pair = [item, now] as unknown as [
            { input: unknown; sync: Outcome; async: Outcome },
            { sync: Outcome; async: Outcome },
        ];
        if (KEY_CASES.includes(item.id)) {
            expectKeyCase(...pair);
            continue;
        }
        if (HIT_ID_CASES.includes(item.id)) {
            expect(JSON.stringify(now.sync)).toBe(JSON.stringify(item.sync));
            expect((now.async as Outcome).out).toEqual((item.async as Outcome).out);
            const ids = (now.async as Outcome).hits.map(([id, start, end]) => [
                id.replace(/^@secretlint\/secretlint-rule-/, ''),
                start,
                end,
            ]);
            expect(ids).toEqual((item.async as Outcome).hits);
            continue;
        }
        if (COLLISION_CASES.includes(item.id)) {
            expectCollisionCase(...pair);
            continue;
        }
        const expected = AWS_CORRECTION[item.id as keyof typeof AWS_CORRECTION];
        expect(item.input).toBe(expected?.input);
        expect(item.async.out).toBe(expected?.recordedOut);
        expect(JSON.stringify(now.sync)).toBe(JSON.stringify(item.sync));
        expect(now.async as unknown).toEqual({ out: expected?.out, hits: expected?.hits });
    }
    const listed = [...Object.keys(AWS_CORRECTION), ...HIT_ID_CASES, ...KEY_CASES, ...COLLISION_CASES];
    expect([...differing].sort()).toEqual([...listed].sort());
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
