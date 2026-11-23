/**
 * place-key.test.ts — key collisions (SPEC 8): no value is lost. A key redaction leaves as it is keeps
 * its name (the input keys that hold a placeholder are reserved); of the changed keys the first keeps its key, the
 * next ones get `#2`, `#3` inside their last placeholder; and `restoreRedacted` maps such keys back.
 */
import { describe, expect, test } from 'bun:test';
import { keysHoldingPlaceholder, newPlacer, placeKey, redactedKeyNames } from './place-key.js';
import { redactJsonValue } from './redact-value.js';
import { redactJsonValueSync } from './redact-sync.js';
import { restoreRedacted } from './restore.js';

type Entry = [key: string, changed: boolean];

function place(entries: Entry[], reserved: string[] = []): string[] {
    const out: Record<string, unknown> = {};
    const placer = newPlacer(new Set(reserved));
    entries.forEach(([key, changed], at) => placeKey(out, placer, key, changed, at));
    return Object.keys(out);
}

describe('placeKey', () => {
    test('changed keys that collide are numbered inside their last placeholder, in order', () => {
        expect(
            place([
                ['[REDACTED:npm]', true],
                ['[REDACTED:npm]', true],
                ['[REDACTED:npm]', true],
            ]),
        ).toEqual(['[REDACTED:npm]', '[REDACTED:npm#2]', '[REDACTED:npm#3]']);
        expect(
            place([
                ['a [REDACTED:npm] b', true],
                ['a [REDACTED:npm] b', true],
            ]),
        ).toEqual(['a [REDACTED:npm] b', 'a [REDACTED:npm#2] b']);
        expect(
            place([
                ['[REDACTED:x] and [REDACTED:y]', true],
                ['[REDACTED:x] and [REDACTED:y]', true],
            ]),
        ).toEqual(['[REDACTED:x] and [REDACTED:y]', '[REDACTED:x] and [REDACTED:y#2]']);
    });

    test('a reserved name is never taken: the first changed key skips it', () => {
        expect(
            place(
                [
                    ['[REDACTED:npm]', true],
                    ['[REDACTED:npm]', false],
                ],
                ['[REDACTED:npm]'],
            ),
        ).toEqual(['[REDACTED:npm#2]', '[REDACTED:npm]']);
    });

    test('a reserved numbered name is skipped, and a later literal numbered key keeps its own name', () => {
        const reserved = ['[REDACTED:npm#2]'];
        expect(
            place(
                [
                    ['[REDACTED:npm]', true],
                    ['[REDACTED:npm]', true],
                    ['[REDACTED:npm#2]', false],
                ],
                reserved,
            ),
        ).toEqual(['[REDACTED:npm]', '[REDACTED:npm#3]', '[REDACTED:npm#2]']);
    });

    test('a last placeholder that is numbered, has a suffix or is not a rule placeholder is not numbered', () => {
        for (const key of ['[REDACTED:npm#2]', '[REDACTED:a:b]', '[REDACTED]', 'no placeholder here']) {
            expect(
                place([
                    [key, true],
                    [key, true],
                ]),
            ).toEqual([key]);
        }
    });

    test('keysHoldingPlaceholder lists the keys that can be reserved', () => {
        expect(keysHoldingPlaceholder(['a', 'x [REDACTED:npm]', '[REDACTED]'])).toEqual([
            'x [REDACTED:npm]',
            '[REDACTED]',
        ]);
    });
});

const NPM_A = `npm_${'A'.repeat(36)}`;
const NPM_B = `npm_${'B'.repeat(36)}`;
const GH_A = `ghp_${'a'.repeat(36)}`;
const GH_B = `ghp_${'b'.repeat(36)}`;
const PW_1 = 'password=Zq9MuIT1yZAN2BE75_x';
const PW_2 = 'password=Zq9SUNzC6gKF6pN5U_x';

async function roundTrip(
    stored: Record<string, unknown>,
): Promise<{ redacted: unknown; restored: unknown; conflicts: string[] }> {
    const redacted = await redactJsonValue(stored, { hits: [] });
    const { value, conflicts } = restoreRedacted(redacted, stored);
    return { redacted, restored: value, conflicts };
}

describe('restoreRedacted maps placeholder keys back', () => {
    test('token keys written back come back with their values, no conflict', async () => {
        const stored = { [NPM_A]: 1, [NPM_B]: 2, plain: 3 };
        const { redacted, restored, conflicts } = await roundTrip(stored);
        expect(Object.keys(redacted as object)).toEqual(['[REDACTED:npm]', '[REDACTED:npm#2]', 'plain']);
        expect(restored).toEqual(stored);
        expect(Object.keys(restored as object)).toEqual([NPM_A, NPM_B, 'plain']);
        expect(conflicts).toEqual([]);
    });

    test('a literal placeholder key next to a token key: no secret moves to another item', async () => {
        const stored = { [GH_A]: { v: 'secret-a' }, '[REDACTED:github]': { v: 'literal' } };
        const { redacted, restored, conflicts } = await roundTrip(stored);
        expect(Object.keys(redacted as object)).toEqual(['[REDACTED:github#2]', '[REDACTED:github]']);
        expect(restored).toEqual(stored);
        expect(Object.keys(restored as object)).toEqual([GH_A, '[REDACTED:github]']);
        expect(conflicts).toEqual([]);
    });

    test('partly replaced keys come back', () => {
        const stored = { [PW_1]: 'one-secret', [PW_2]: 'two-secret' };
        const redacted = redactJsonValueSync(stored);
        expect(Object.keys(redacted as object)).toEqual([
            'password=[REDACTED:generic-keyword]',
            'password=[REDACTED:generic-keyword#2]',
        ]);
        expect(restoreRedacted(redacted, stored)).toEqual({ value: stored, conflicts: [] });
    });

    test('a key redacted by the standard rules comes back too', () => {
        const stored = { [GH_A]: 1, [GH_B]: 2 };
        const redacted = redactJsonValueSync(stored);
        expect(Object.keys(redacted as object)).toEqual(['[REDACTED:github]', '[REDACTED:github#2]']);
        expect(restoreRedacted(redacted, stored)).toEqual({ value: stored, conflicts: [] });
    });

    test('a value under a restored key is restored against the stored value', () => {
        const stored = { [GH_A]: { token: 'keep-this-secret-1', other: 'x' } };
        const incoming = { '[REDACTED:github]': { token: '[REDACTED:key-context]', other: 'changed' } };
        expect(restoreRedacted(incoming, stored)).toEqual({
            value: { [GH_A]: { token: 'keep-this-secret-1', other: 'changed' } },
            conflicts: [],
        });
    });

    test('a placeholder key with no stored key stays and is a conflict', () => {
        const result = restoreRedacted({ '[REDACTED:npm]': 1, '[REDACTED:npm#2]': 2 }, { [NPM_A]: 1 });
        expect(Object.keys(result.value as object)).toEqual([NPM_A, '[REDACTED:npm#2]']);
        expect(result.conflicts).toEqual(['$["[REDACTED:npm#2]"]']);
        expect(restoreRedacted({ '[REDACTED:npm]': 1 }, {}).conflicts).toEqual(['$["[REDACTED:npm]"]']);
    });

    test('two incoming keys for one stored key: the second stays and is a conflict', () => {
        const stored = { [`token ${NPM_A}`]: 1 };
        const incoming = { 'token [REDACTED:auth-header]': 1, 'token [REDACTED:npm]': 2 };
        const result = restoreRedacted(incoming, stored);
        expect(Object.keys(result.value as object)).toEqual([`token ${NPM_A}`, 'token [REDACTED:npm]']);
        expect(result.conflicts).toEqual(['$["token [REDACTED:npm]"]']);
    });

    test('numbered placeholders as values restore like the plain ones', () => {
        for (const placeholder of ['[REDACTED:npm]', '[REDACTED:npm#2]']) {
            expect(restoreRedacted({ a: placeholder }, { a: 'secret-value-1' })).toEqual({
                value: { a: 'secret-value-1' },
                conflicts: [],
            });
            expect(restoreRedacted({ a: placeholder }, {}).conflicts).toEqual(['$.a']);
        }
        expect(restoreRedacted({ a: 'x [REDACTED:npm#2] y' }, { a: 'x secret y' })).toEqual({
            value: { a: 'x secret y' },
            conflicts: [],
        });
    });

    test('the key names are the placement of the walkers', () => {
        const names = redactedKeyNames([NPM_A, '[REDACTED:npm]', NPM_B], () => []);
        expect([...names.keys()]).toEqual([NPM_A, '[REDACTED:npm]', NPM_B]);
    });
});

describe('restore conflict paths never hold a stored key (A1)', () => {
    test('a conflict below a restored key is named by the placeholder key the client sent', () => {
        const npm = restoreRedacted(
            { '[REDACTED:npm]': { tok: '[REDACTED:stripe]' } },
            { [NPM_A]: { tok: null } },
        );
        expect(npm.conflicts).toEqual(['$["[REDACTED:npm]"].tok']);
        const partly = restoreRedacted(
            { 'password=[REDACTED:generic-keyword]': { tok: '[REDACTED:stripe]' } },
            { [PW_1]: { tok: null } },
        );
        expect(partly.conflicts).toEqual(['$["password=[REDACTED:generic-keyword]"].tok']);
    });

    test('over seeded documents no conflict path contains a stored key or a secret', () => {
        const secrets = [NPM_A, NPM_B, GH_A, GH_B, PW_1, PW_2];
        let state = 12345;
        const next = (limit: number): number => {
            state = (state * 1103515245 + 12345) % 2147483648;
            return state % limit;
        };
        let conflictsSeen = 0;
        for (let round = 0; round < 300; round++) {
            const stored: Record<string, unknown> = {};
            for (const secret of secrets)
                if (next(2) === 0) stored[secret] = { tok: next(2) === 0 ? null : 'v' };
            if (next(2) === 0) stored['[REDACTED:npm]'] = { tok: null };
            const redacted = redactJsonValueSync(stored) as Record<string, unknown>;
            const incoming = Object.fromEntries(
                Object.keys(redacted)
                    .filter((key) => key.includes('[REDACTED'))
                    .map((key) => [key, { tok: '[REDACTED:stripe]' }]),
            );
            const { conflicts } = restoreRedacted(incoming, stored);
            conflictsSeen += conflicts.length;
            for (const path of conflicts) for (const secret of secrets) expect(path).not.toContain(secret);
        }
        expect(conflictsSeen).toBeGreaterThan(200);
    });
});
