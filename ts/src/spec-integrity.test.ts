/**
 * spec-integrity.test.ts — the spec the package runs on is the spec in `spec/`: the generated module
 * equals the three data files and carries their hash, and the package refuses to start on an
 * unsupported version or an empty rule set. (The hash itself is checked here and by `sync-spec --check`
 * in CI and on release; there is no runtime hash check.)
 */
import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { renderSpecModule, specHash } from '../../tools/sync-spec.ts';
import { ALGORITHMS_DATA, KEYS_DATA, RULES_DATA, SPEC_HASH } from './spec-data.generated.js';

const PACKAGE_DIR = join(import.meta.dir, '..');
const SPEC_DIR = join(PACKAGE_DIR, '..', 'spec');
const FILES = ['rules.json', 'keys.json', 'algorithms.json'] as const;

const readSpec = (name: string): Buffer => readFileSync(join(SPEC_DIR, name));

test('the generated module holds exactly the data of spec/*.json', () => {
    expect(RULES_DATA).toEqual(JSON.parse(readSpec('rules.json').toString('utf8')));
    expect(KEYS_DATA).toEqual(JSON.parse(readSpec('keys.json').toString('utf8')));
    expect(ALGORITHMS_DATA).toEqual(JSON.parse(readSpec('algorithms.json').toString('utf8')));
});

test('the generated module is byte-identical to what sync-spec renders, hash included', () => {
    const rendered = renderSpecModule(readSpec);
    expect(readFileSync(join(PACKAGE_DIR, 'src', 'spec-data.generated.ts'), 'utf8')).toBe(rendered);
    expect(SPEC_HASH).toBe(specHash(readSpec));
});

test('the hash covers every data file: a changed byte in any of them changes it', () => {
    for (const changed of FILES) {
        const edited = (name: string): Buffer => {
            const bytes = readSpec(name);
            return name === changed ? Buffer.concat([bytes, Buffer.from(' ')]) : bytes;
        };
        expect(specHash(edited)).not.toBe(SPEC_HASH);
    }
});

function importWith(rules: object | undefined, version?: number): { status: number | null; stderr: string } {
    const dir = mkdtempSync(join(tmpdir(), 'redaction-spec-'));
    try {
        cpSync(join(PACKAGE_DIR, 'src'), join(dir, 'src'), { recursive: true });
        if (rules !== undefined) {
            const edited = (name: string): Buffer => {
                if (name !== 'rules.json') return readSpec(name);
                return Buffer.from(
                    JSON.stringify({ ...rules, ...(version ? { specVersion: version } : {}) }),
                );
            };
            writeFileSync(join(dir, 'src', 'spec-data.generated.ts'), renderSpecModule(edited));
        }
        const result = spawnSync(process.execPath, ['--eval', "await import('./src/sync.ts');"], {
            cwd: dir,
            encoding: 'utf8',
            timeout: 20_000,
        });
        return { status: result.status, stderr: result.stderr };
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}

const RULES = JSON.parse(readSpec('rules.json').toString('utf8')) as { pipeline: unknown[] };

test('an unmodified copy of the package imports', () => {
    expect(importWith(undefined).status).toBe(0);
});

test('a spec with no rules fails the import', () => {
    const outcome = importWith({ ...RULES, pipeline: [] });
    expect(outcome.status).not.toBe(0);
    expect(outcome.stderr).toContain('holds no rules');
});

test('a spec of another version fails the import', () => {
    const outcome = importWith(RULES, 2);
    expect(outcome.status).not.toBe(0);
    expect(outcome.stderr).toContain('unsupported redaction spec version');
});
