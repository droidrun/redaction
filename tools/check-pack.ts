#!/usr/bin/env bun
/**
 * check-pack — builds the TypeScript package, packs it, and imports it from the tarball the way a
 * consumer would: the main entry, the `./sync` entry and a vector file through the `./vectors/*.json`
 * subpath, then redacts a secret with the packed code (also one only the full tier finds). The package has no
 * runtime dependency: the consumer directory holds nothing but the tarball, and no packed file may import
 * `@secretlint`. Run from anywhere; exits 1 on any failure.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
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
const npmToken = 'npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';
assert.equal((await full.redactText('see ' + npmToken + ' ok')).text, 'see [REDACTED:npm] ok');
assert.equal(sync.redactTextSync('see ' + npmToken + ' ok').text, 'see ' + npmToken + ' ok');
const require = createRequire(import.meta.url);
assert.throws(() => require.resolve('@droidrun/redaction/spec/rules.json'));
console.log('consumer import ok');
`;

/** `from '@secretlint/..'`, `import('@secretlint/..')`, `require('@secretlint/..')`. */
const IMPORT_OF_SECRETLINT = /(?:from|import\(|require\()\s*['"]@secretlint\//;

function distFiles(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
        entry.isDirectory() ? distFiles(join(dir, entry.name)) : [join(dir, entry.name)],
    );
}

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
    const manifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8')) as {
        dependencies?: Record<string, string>;
    };
    if (Object.keys(manifest.dependencies ?? {}).length > 0) {
        console.error('the packed package has runtime dependencies; it must have none');
        process.exit(1);
    }
    const mentions = distFiles(join(installed, 'dist')).filter((file) =>
        IMPORT_OF_SECRETLINT.test(readFileSync(file, 'utf8')),
    );
    if (mentions.length > 0) {
        console.error(`the packed runtime mentions @secretlint:\n${mentions.join('\n')}`);
        process.exit(1);
    }
    const vectorFiles = readdirSync(join(installed, 'vectors'));
    if (!vectorFiles.includes('auth-headers.json')) {
        console.error('the tarball holds no vectors');
        process.exit(1);
    }
    for (const legal of ['LICENSE', 'NOTICE']) {
        if (!existsSync(join(installed, legal))) {
            console.error(`the tarball holds no ${legal}`);
            process.exit(1);
        }
    }
    if (existsSync(join(installed, 'spec'))) {
        console.error('the tarball holds a spec/ directory: the package must run from its generated module');
        process.exit(1);
    }
    run('node', ['--input-type=module', '--eval', CONSUMER], consumer);
    console.log(`check-pack: ok (${filename}, ${vectorFiles.length} vector files)`);
} finally {
    rmSync(work, { recursive: true, force: true });
}
