/**
 * license-copies.test.ts — the license and the third-party notices are copied into every package directory
 * (the Go module zip holds only go/, the npm package and the wheel only their own directory): the copies must be
 * byte-identical to the root files.
 */
import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dir, '..');
const read = (path: string): string => readFileSync(join(ROOT, path), 'utf8');

test('LICENSE is copied into ts, python and go', () => {
    for (const dir of ['ts', 'python', 'go']) expect(read(`${dir}/LICENSE`)).toBe(read('LICENSE'));
});

test('THIRD_PARTY_NOTICES.md is mirrored as NOTICE in ts, python and go', () => {
    for (const dir of ['ts', 'python', 'go'])
        expect(read(`${dir}/NOTICE`)).toBe(read('THIRD_PARTY_NOTICES.md'));
});

test('the fixture license is the upstream MIT text and the notices quote it', () => {
    const upstream = read('spec/corpus/secretlint-13.0.4/LICENSE').trimEnd();
    expect(upstream).toContain('Copyright (c) 2020 azu');
    expect(read('THIRD_PARTY_NOTICES.md')).toContain(upstream);
});
