import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// A fresh process isolates this check from the parity suite's dev-only core
// import. Bun exposes evaluated ESM modules in require.cache as well as CJS.
test('the public entry scans 300 kB without loading core or profiler', () => {
    const result = spawnSync(process.execPath, ['--eval', `
        import { strict as assert } from 'node:assert';
        const { redactText } = await import('./src/index.ts');
        const secret = 'S0mmer2026!xTr0ub4dor';
        const input = 'x'.repeat(150_000) + ' password: ' + secret + ' ' + 'y'.repeat(150_000);
        const { text, hits } = await redactText(input);
        assert.equal(hits.length, 1);
        assert.equal(text.includes(secret), false);
        assert.equal(text.includes('[REDACTED:generic-keyword:4dor]'), true);
        const forbidden = Object.keys(require.cache).filter((path) =>
            path.includes('@secretlint/core/') || path.includes('@secretlint/profiler/'));
        assert.deepEqual(forbidden, []);
    `], {
        cwd: fileURLToPath(new URL('..', import.meta.url)),
        encoding: 'utf8',
        timeout: 10_000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
}, 20_000);
