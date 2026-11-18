/**
 * spec-integrity.test.ts — the package refuses to start on a spec copy that does not
 * match its generated hash, and on one that holds no rules.
 */
import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hashSpecFiles } from './spec.js';

const PACKAGE_DIR = join(import.meta.dir, '..');

function importIn(dir: string): { status: number | null; stderr: string } {
    const result = spawnSync(process.execPath, ['--eval', "await import('./src/sync.ts');"], {
        cwd: dir,
        encoding: 'utf8',
        timeout: 20_000,
    });
    return { status: result.status, stderr: result.stderr };
}

function withCopy(edit: (dir: string) => void): { status: number | null; stderr: string } {
    const dir = mkdtempSync(join(tmpdir(), 'redaction-spec-'));
    try {
        cpSync(join(PACKAGE_DIR, 'src'), join(dir, 'src'), { recursive: true });
        cpSync(join(PACKAGE_DIR, 'spec'), join(dir, 'spec'), { recursive: true });
        edit(dir);
        return importIn(dir);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}

test('an unmodified copy imports', () => {
    expect(withCopy(() => {}).status).toBe(0);
});

test('a changed rule value makes the import fail on the hash', () => {
    const outcome = withCopy((dir) => {
        const path = join(dir, 'spec', 'algorithms.json');
        writeFileSync(path, readFileSync(path, 'utf8').replace('"minClasses": 3', '"minClasses": 2'));
    });
    expect(outcome.status).not.toBe(0);
    expect(outcome.stderr).toContain('does not match its hash');
});

test('a spec with no rules fails the import even when its hash matches', () => {
    const outcome = withCopy((dir) => {
        const rulesPath = join(dir, 'spec', 'rules.json');
        const rules = JSON.parse(readFileSync(rulesPath, 'utf8')) as { pipeline: unknown[] };
        rules.pipeline = [];
        writeFileSync(rulesPath, JSON.stringify(rules, null, 2));
        const hash = hashSpecFiles((name) => readFileSync(join(dir, 'spec', name)));
        writeFileSync(join(dir, 'src', 'spec-hash.generated.ts'), `export const SPEC_HASH = '${hash}';\n`);
    });
    expect(outcome.status).not.toBe(0);
    expect(outcome.stderr).toContain('holds no rules');
});
