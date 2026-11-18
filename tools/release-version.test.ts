/**
 * release-version.test.ts — the version is SemVer X.Y.Z (no leading zeros), is set and checked in every place, and a
 * place that differs fails the check. The script runs on a copy of the four files (RELEASE_VERSION_ROOT).
 */
import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { isVersion } from './release-version.ts';

const REPO = resolve(import.meta.dir, '..');
const FILES = ['ts/package.json', 'python/pyproject.toml', 'python/uv.lock', 'go/version.go'];

function withCopy<T>(run: (root: string) => T): T {
    const root = mkdtempSync(join(tmpdir(), 'release-version-'));
    try {
        for (const file of FILES) {
            mkdirSync(dirname(join(root, file)), { recursive: true });
            cpSync(join(REPO, file), join(root, file));
        }
        return run(root);
    } finally {
        rmSync(root, { recursive: true, force: true });
    }
}

function script(root: string, ...args: string[]): { status: number | null; out: string } {
    const result = spawnSync('bun', [join(REPO, 'tools', 'release-version.ts'), ...args], {
        env: { ...process.env, RELEASE_VERSION_ROOT: root },
        encoding: 'utf8',
    });
    return { status: result.status, out: `${result.stdout}${result.stderr}` };
}

test.each(['0.0.0', '0.2.0', '1.0.0', '10.20.30'])('%s is a version', (text) => {
    expect(isVersion(text)).toBe(true);
});

test.each(['01.2.3', '1.02.3', '1.2.03', '00.0.0', '1.2', '1.2.3.4', 'v1.2.3', '1.2.3-rc.1', '1.2.x', ''])(
    '%s is not a version',
    (text) => {
        expect(isVersion(text)).toBe(false);
    },
);

test('setting a version with a leading zero is refused and changes nothing', () => {
    withCopy((root) => {
        const before = readFileSync(join(root, 'ts/package.json'), 'utf8');
        for (const bad of ['01.2.3', '1.02.3']) expect(script(root, bad).status).not.toBe(0);
        expect(readFileSync(join(root, 'ts/package.json'), 'utf8')).toBe(before);
    });
});

test('a version that is set shows in all four places and passes the check, with and without a tag', () => {
    withCopy((root) => {
        expect(script(root, '3.4.5').status).toBe(0);
        for (const file of FILES) expect(readFileSync(join(root, file), 'utf8')).toContain('3.4.5');
        expect(script(root, '--check').status).toBe(0);
        expect(script(root, '--check', 'v3.4.5').status).toBe(0);
        expect(script(root, '--check', 'go/v3.4.5').status).toBe(0);
        expect(script(root, '--check', 'v3.4.6').status).not.toBe(0);
    });
});

test('a leading-zero version found in all places fails the check', () => {
    withCopy((root) => {
        for (const file of FILES) {
            const path = join(root, file);
            writeFileSync(path, readFileSync(path, 'utf8').replaceAll('0.2.0', '01.2.3'));
        }
        const result = script(root, '--check');
        expect(result.status).not.toBe(0);
        expect(result.out).toContain('X.Y.Z');
    });
});

test('one place that differs fails the check and names the places', () => {
    withCopy((root) => {
        const path = join(root, 'go/version.go');
        writeFileSync(path, readFileSync(path, 'utf8').replace('0.2.0', '0.2.1'));
        const result = script(root, '--check');
        expect(result.status).not.toBe(0);
        expect(result.out).toContain('the versions differ');
    });
});
