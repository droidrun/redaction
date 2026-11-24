/**
 * selection.test.ts — `--only` narrows to the patterns of the named rule ids or kinds and to the attack units that
 * belong to them; the interpreter scaling runs only when such units exist; an unknown name is reported.
 */
import { expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { lintDir } from '../lint-spec.ts';
import { FileGateCache } from './recheck-cache.ts';
import { attacksFor } from './attacks.ts';
import { scopeFor, unknownOnly } from './selection.ts';
import { collectPatterns, readSpecDir } from './spec-patterns.ts';

const spec = readSpecDir(resolve(import.meta.dir, '..', '..', 'spec'));
const patterns = collectPatterns(spec);
const wheres = (found: typeof patterns): string[] => found.map((pattern) => pattern.where);

test('--only email selects exactly the patterns of the email rule', () => {
    const scope = scopeFor(spec, patterns, ['email']);
    const expected = patterns.filter((pattern) => pattern.rule?.id === 'email');
    expect(expected.length).toBe(scope.patterns.length);
    expect(wheres(scope.patterns)).toEqual(wheres(expected));
    expect(scope.patterns.length).toBeGreaterThan(0);
    expect(scope.patterns.length).toBeLessThan(patterns.length);
});

test('--only email keeps the generic attack units, drops those of the token rules and skips the interpreter', () => {
    const scope = scopeFor(spec, patterns, ['email']);
    const all = attacksFor(spec);
    expect(scope.attacks.length).toBeLessThan(all.length);
    expect(scope.attacks.some((attack) => attack.name === JSON.stringify('Bearer '))).toBe(true);
    expect(scope.attacks.some((attack) => attack.name.includes('glpat-'))).toBe(false);
    expect(scope.interpreterAttacks).toBeUndefined();
    expect(scope.skipped.join('\n')).toContain('interpreter scaling skipped');
});

test('--only gitlab adds the units of that token rule and runs the interpreter over them', () => {
    const scope = scopeFor(spec, patterns, ['gitlab']);
    expect(scope.attacks.some((attack) => attack.name.includes('glpat-'))).toBe(true);
    expect(scope.attacks.some((attack) => attack.name.includes('xoxb-a-1'))).toBe(false);
    expect(scope.interpreterAttacks?.every((attack) => attack.name.includes('glpat-'))).toBe(true);
});

test('a kind selects every rule of that kind', () => {
    const scope = scopeFor(spec, patterns, ['credential-uri']);
    const kinds = new Set(scope.patterns.map((pattern) => pattern.rule?.kind));
    expect([...kinds]).toEqual(['credential-uri']);
    expect(scope.patterns.length).toBeGreaterThan(1);
});

test('without --only nothing is narrowed', () => {
    const scope = scopeFor(spec, patterns, undefined);
    expect(scope.patterns).toBe(patterns);
    expect(scope.attacks).toEqual(attacksFor(spec));
    expect(scope.interpreterAttacks).toEqual(attacksFor(spec));
    expect(scope.skipped).toEqual([]);
});

test('an unknown name is reported, a known id or kind is not', () => {
    expect(unknownOnly(patterns, ['email', 'token', 'emial'])).toEqual([
        '--only: no rule id or kind named emial',
    ]);
});

test('--only-scaling with an unknown name reports it before any run', async () => {
    const problems = await lintDir(resolve(import.meta.dir, '..', '..', 'spec'), {
        scaling: true,
        recheck: true,
        scalingOnly: true,
        only: ['definitely-not-a-rule'],
    });
    expect(problems).toEqual(['--only: no rule id or kind named definitely-not-a-rule']);
});

test('a run without recheck leaves the cache file as it was', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'lint-cache-'));
    try {
        const path = join(dir, 'gate.json');
        const seeded = new FileGateCache(path);
        seeded.set('stale', {});
        seeded.save(false);
        const options = { scaling: false, recheck: false, cache: new FileGateCache(path) };
        await lintDir(resolve(import.meta.dir, '..', '..', 'spec'), options);
        expect(new FileGateCache(path).get('stale')).toEqual({});
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}, 60_000);
