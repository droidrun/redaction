/**
 * runtime-free.test.ts — importing `./sync` or the full entry needs no Node built-in, file access or
 * `import.meta` in this package's own code: every module reachable from the entries through relative
 * imports is scanned (the full-tier rules are part of that code; secretlint is no dependency).
 */
import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const SRC = join(import.meta.dir);
const RELATIVE_IMPORT = /(?:from|import)\s+['"](\.\.?\/[^'"]+)['"]/g;
const FORBIDDEN = [/['"]node:[a-z/_]+['"]/, /import\.meta/, /\brequire\(/, /\bprocess\./, /\bBuffer\b/];

function reachable(entry: string): string[] {
    const seen = new Set<string>();
    const queue = [resolve(SRC, entry)];
    while (queue.length > 0) {
        const file = queue.pop() as string;
        if (seen.has(file)) continue;
        seen.add(file);
        const source = readFileSync(file, 'utf8');
        for (const match of source.matchAll(RELATIVE_IMPORT)) {
            queue.push(resolve(dirname(file), (match[1] as string).replace(/\.js$/, '.ts')));
        }
    }
    return [...seen];
}

test.each(['sync.ts', 'index.ts'])('%s reaches no Node built-in, import.meta or process', (entry) => {
    const files = reachable(entry);
    expect(files.length).toBeGreaterThan(10);
    const offenders = files.flatMap((file) => {
        const source = readFileSync(file, 'utf8');
        return FORBIDDEN.filter((pattern) => pattern.test(source)).map((pattern) => `${file}: ${pattern}`);
    });
    expect(offenders).toEqual([]);
});
