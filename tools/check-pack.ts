#!/usr/bin/env bun
/**
 * check-pack — builds the TypeScript package, packs it, and imports it from the tarball the way a
 * consumer would: the main entry, the `./sync` entry and a vector file through the `./vectors/*.json`
 * subpath, then redacts a secret with the packed code. Dependencies are linked from `ts/node_modules`
 * (no network). Run from anywhere; exits 1 on any failure.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dir, '..');
const TS = join(ROOT, 'ts');

function run(command: string, args: string[], cwd: string, env: NodeJS.ProcessEnv = {}): string {
    const result = spawnSync(command, args, {
        cwd,
        encoding: 'utf8',
        timeout: 180_000,
        env: { ...process.env, ...env },
    });
    if (result.status !== 0) {
        console.error(`${command} ${args.join(' ')} failed:\n${result.stdout}\n${result.stderr}`);
        process.exit(1);
    }
    return result.stdout;
}

const CONSUMER = `
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
const full = await import('@droidrun/redaction');
const sync = await import('@droidrun/redaction/sync');
const vector = await import('@droidrun/redaction/vectors/auth-headers.json', { with: { type: 'json' } });
assert.equal(typeof full.redactText, 'function');
assert.equal(typeof sync.redactTextSync, 'function');
assert.ok(vector.default.cases.length > 0);
assert.equal(
    sync.redactTextSync('login password: Zq9fakeMARKER_x1').text,
    'login password: [REDACTED:generic-keyword]',
);
assert.equal((await full.redactText('login password: Zq9fakeMARKER_x1')).text,
    'login password: [REDACTED:generic-keyword]');
const require = createRequire(import.meta.url);
assert.throws(() => require.resolve('@droidrun/redaction/spec/rules.json'));
console.log('consumer import ok');
`;

const work = mkdtempSync(join(tmpdir(), 'redaction-pack-'));
try {
    run('pnpm', ['run', 'build'], TS);
    const packOut = run('npm', ['pack', '--pack-destination', work, '--json'], TS, {
        npm_config_cache: join(work, 'npm-cache'),
    });
    const parsed = JSON.parse(packOut) as { filename: string }[] | Record<string, { filename: string }>;
    const { filename } = (Array.isArray(parsed) ? parsed[0] : Object.values(parsed)[0]) as {
        filename: string;
    };
    const consumer = join(work, 'consumer');
    const installed = join(consumer, 'node_modules', '@droidrun', 'redaction');
    mkdirSync(installed, { recursive: true });
    run('tar', ['-xzf', join(work, filename), '-C', installed, '--strip-components=1'], work);
    symlinkSync(join(TS, 'node_modules', '@secretlint'), join(consumer, 'node_modules', '@secretlint'));
    const vectorFiles = readdirSync(join(installed, 'spec', 'vectors'));
    if (!vectorFiles.includes('auth-headers.json')) {
        console.error('the tarball holds no spec/vectors');
        process.exit(1);
    }
    run('node', ['--input-type=module', '--eval', CONSUMER], consumer);
    console.log(`check-pack: ok (${filename}, ${vectorFiles.length} vector files)`);
} finally {
    rmSync(work, { recursive: true, force: true });
}
