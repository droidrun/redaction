/**
 * sync-entry.test.ts — the `./sync` subpath: importing it must not load the full tier (no full-only algorithm module)
 * (the logger and edge workers import only this), no entry loads secretlint, and it
 * exports the same functions as the full entry.
 */
import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as full from './index.js';
import * as sync from './sync.js';

test('importing the sync entry loads no full-tier algorithm and no secretlint module', () => {
    const result = spawnSync(process.execPath, ['--eval', `
        import { strict as assert } from 'node:assert';
        const sync = await import('./src/sync.ts');
        const out = sync.redactTextSync('login password: Zq9fakeMARKER_x1');
        assert.equal(out.text, 'login password: [REDACTED:generic-keyword]');
        assert.equal(sync.restoreRedacted({ a: '[REDACTED]' }, { a: 'x' }).value.a, 'x');
        const fullOnly = /secretlint|full-rules|full-registry|algorithms.(token|dash-chain|sendgrid|pem-key|credential-uri|base64-json|letters|scan-support)/;
        const loaded = Object.keys(require.cache).filter((path) => fullOnly.test(path));
        assert.deepEqual(loaded, []);
    `], {
        cwd: fileURLToPath(new URL('..', import.meta.url)),
        encoding: 'utf8',
        timeout: 10_000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
}, 20_000);

test('the full entry loads the full tier and still no secretlint module (so the check above can fail)', () => {
    const result = spawnSync(process.execPath, ['--eval', `
        import { strict as assert } from 'node:assert';
        await import('./src/index.ts');
        const paths = Object.keys(require.cache);
        assert.notEqual(paths.filter((path) => path.includes('full-rules')).length, 0);
        assert.deepEqual(paths.filter((path) => path.includes('secretlint')), []);
    `], {
        cwd: fileURLToPath(new URL('..', import.meta.url)),
        encoding: 'utf8',
        timeout: 10_000,
    });
    expect(result.status, result.stderr).toBe(0);
}, 20_000);

test('every export of the sync entry is the same function as the full entry exports', () => {
    for (const [name, value] of Object.entries(sync)) {
        expect((full as Record<string, unknown>)[name], name).toBe(value);
    }
});
