/**
 * tag-go-module.test.ts — the Go tag step, run with a fake `gh` that answers like the GitHub API: a new
 * tag is created on the release commit; a lightweight or an annotated tag on the same commit is accepted (re-run);
 * a tag on another commit fails; a missing tag is created exactly once.
 */
import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const SCRIPT = resolve(import.meta.dir, 'tag-go-module');
const COMMIT = 'a'.repeat(40);
const OTHER = 'b'.repeat(40);
const TAG_OBJECT = 'c'.repeat(40);

type Existing = { type: 'commit' | 'tag'; sha: string; inner?: { type: string; sha: string } } | undefined;

/** A `gh` that knows one existing tag ref (or none) and logs every call. */
function run(existing: Existing): { status: number | null; log: string; out: string } {
    const dir = mkdtempSync(join(tmpdir(), 'tag-go-'));
    try {
        const log = join(dir, 'calls.log');
        const lookup = existing === undefined ? 'exit 1' : `echo "${existing.type} ${existing.sha}"`;
        const inner =
            existing?.inner === undefined ? 'exit 1' : `echo "${existing.inner.type} ${existing.inner.sha}"`;
        writeFileSync(
            join(dir, 'gh'),
            `#!/bin/sh
echo "$*" >> "${log}"
case "$*" in
  *"-X POST"*) exit 0 ;;
  *"git/ref/tags/"*) ${lookup} ;;
  *"git/tags/"*) ${inner} ;;
esac
`,
        );
        chmodSync(join(dir, 'gh'), 0o755);
        const result = spawnSync('sh', [SCRIPT], {
            env: {
                PATH: `${dir}:${process.env.PATH}`,
                GITHUB_REPOSITORY: 'o/r',
                GITHUB_REF_NAME: 'v0.3.0',
                GITHUB_SHA: COMMIT,
            },
            encoding: 'utf8',
        });
        let calls = '';
        try {
            calls = readFileSync(log, 'utf8');
        } catch {
            calls = '';
        }
        return { status: result.status, log: calls, out: `${result.stdout}${result.stderr}` };
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
}

test('a missing tag is created once, on the release commit, as go/vX.Y.Z', () => {
    const result = run(undefined);
    expect(result.status).toBe(0);
    const posts = result.log.split('\n').filter((line) => line.includes('-X POST'));
    expect(posts).toHaveLength(1);
    expect(posts[0]).toContain('refs/tags/go/v0.3.0');
    expect(posts[0]).toContain(COMMIT);
});

test('a lightweight tag on the same commit is accepted and nothing is created', () => {
    const result = run({ type: 'commit', sha: COMMIT });
    expect(result.status).toBe(0);
    expect(result.log).not.toContain('-X POST');
});

test('an annotated tag whose commit is the same is peeled and accepted', () => {
    const result = run({ type: 'tag', sha: TAG_OBJECT, inner: { type: 'commit', sha: COMMIT } });
    expect(result.status).toBe(0);
    expect(result.log).toContain(`git/tags/${TAG_OBJECT}`);
    expect(result.log).not.toContain('-X POST');
});

test('a tag on another commit fails, annotated or not', () => {
    expect(run({ type: 'commit', sha: OTHER }).status).toBe(1);
    const annotated = run({ type: 'tag', sha: TAG_OBJECT, inner: { type: 'commit', sha: OTHER } });
    expect(annotated.status).toBe(1);
    expect(annotated.out).toContain('does not point at the commit');
});
