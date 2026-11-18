#!/usr/bin/env bun
/**
 * Cross-language differential test: runs the same seeded cases through the TypeScript, Python and Go runners
 * (protocol: protocol.ts) and requires byte-identical output and equal rule-id counts wherever two or more
 * runners implement the (tier, mode). A tier a language does not have yet is skipped by its capability line.
 *
 *   bun tools/diff/driver.ts [--only ts,python,go] [--limit N] [--show N]
 *
 * Exit 1 on any difference, a runner that fails to start or stops answering, or fewer than 5,000 cases.
 */
import { spawn, spawnSync, type ChildProcessByStdio } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { allCases, type DiffCase } from './cases.ts';
import {
    canonicalJson,
    countKey,
    lines,
    toLine,
    type Capabilities,
    type Mode,
    type Request,
    type Tier,
} from './protocol.ts';

const ROOT = resolve(import.meta.dir, '..', '..');
const TIERS: Tier[] = ['standard', 'full'];
const MODES: Mode[] = ['compat', 'strict'];
const MIN_CASES = 5000;
const DEADLINE_MS = 25 * 60 * 1000;

type RunnerSpec = { name: string; command: string; args: string[]; cwd: string };

function goRunner(work: string): RunnerSpec {
    const binary = join(work, 'diffrunner-go');
    const built = spawnSync('go', ['build', '-o', binary, './internal/diffrunner'], {
        cwd: join(ROOT, 'go'),
        encoding: 'utf8',
    });
    if (built.status !== 0) throw new Error(`go build failed: ${built.stderr.slice(0, 500)}`);
    return { name: 'go', command: binary, args: [], cwd: join(ROOT, 'go') };
}

function runnerSpecs(only: string[], work: string): RunnerSpec[] {
    const all: Record<string, () => RunnerSpec> = {
        ts: () => ({ name: 'ts', command: 'bun', args: [join(ROOT, 'tools/diff/runner-ts.ts')], cwd: ROOT }),
        python: () => ({
            name: 'python',
            command: 'uv',
            args: ['run', '--locked', 'python', 'scripts/diffrunner.py'],
            cwd: join(ROOT, 'python'),
        }),
        go: () => goRunner(work),
    };
    return only.map((name) =>
        (
            all[name] ??
            (() => {
                throw new Error(`unknown runner ${name}`);
            })
        )(),
    );
}

class Runner {
    readonly lines = new Map<string, string>();
    capabilities: Capabilities = { standard: [], full: [] };
    private readonly child: ChildProcessByStdio<Writable, Readable, null>;
    private readonly ready: Promise<void>;
    private readonly closed: Promise<number | null>;

    constructor(readonly spec: RunnerSpec) {
        const child = spawn(spec.command, spec.args, { cwd: spec.cwd, stdio: ['pipe', 'pipe', 'inherit'] });
        this.child = child;
        let first = true;
        let markReady: () => void = () => {};
        this.ready = new Promise((resolveReady) => (markReady = resolveReady));
        void (async () => {
            for await (const line of lines(child.stdout)) {
                if (first) {
                    first = false;
                    this.capabilities = (JSON.parse(line) as { capabilities: Capabilities }).capabilities;
                    markReady();
                    continue;
                }
                const id = (JSON.parse(line.slice(0, line.indexOf(',"out"')) + '}') as { id: string }).id;
                this.lines.set(id, line);
            }
        })();
        this.closed = new Promise((resolveClosed) => child.on('close', resolveClosed));
        child.stdin.on('error', () => {});
    }

    async capabilitiesLine(): Promise<Capabilities> {
        await Promise.race([
            this.ready,
            this.closed.then(() => {
                throw new Error(`runner ${this.spec.name} stopped before its capability line`);
            }),
        ]);
        return this.capabilities;
    }

    async send(requests: Request[]): Promise<void> {
        for (let i = 0; i < requests.length; i += 200) {
            const chunk = requests
                .slice(i, i + 200)
                .map((request) => `${toLine(request)}\n`)
                .join('');
            if (!this.child.stdin.write(chunk)) await new Promise((r) => this.child.stdin.once('drain', r));
        }
    }

    async finish(): Promise<void> {
        this.child.stdin.end();
        const code = await this.closed;
        if (code !== 0) throw new Error(`runner ${this.spec.name} exited with ${code}`);
    }
}

type Parsed = { out: string; counts: string };

function parse(line: string | undefined): Parsed | undefined {
    if (line === undefined) return undefined;
    const outStart = line.indexOf('"out":') + 6;
    const hitsStart = line.lastIndexOf(',"hits":');
    const hitsAndError = JSON.parse(`{${line.slice(hitsStart + 1)}`) as { hits: Array<[string, number]> };
    return { out: canonicalJson(line.slice(outStart, hitsStart)), counts: countKey(hitsAndError.hits) };
}

function requestsFor(cases: DiffCase[], tier: Tier, mode: Mode): Request[] {
    return cases
        .filter((item) => item.modes === undefined || item.modes.includes(mode))
        .map((item) => ({
            id: `${item.id}|${tier}|${mode}`,
            kind: item.kind,
            tier,
            mode,
            opts: item.opts,
            input: item.input,
        }));
}

function clip(text: string, length = 300): string {
    return text.length > length ? `${text.slice(0, length)}… (${text.length} chars)` : text;
}

type Row = { tier: Tier; mode: Mode; runners: string[]; sent: number; compared: number; differing: number };

function compare(runners: Runner[], cases: DiffCase[], show: number): { rows: Row[]; failures: string[] } {
    const rows: Row[] = [];
    const failures: string[] = [];
    const byId = new Map(cases.map((item) => [item.id, item]));
    for (const tier of TIERS) {
        for (const mode of MODES) {
            const active = runners.filter((runner) => runner.capabilities[tier]?.includes(mode));
            const requests = requestsFor(cases, tier, mode);
            const row: Row = {
                tier,
                mode,
                runners: active.map((runner) => runner.spec.name),
                sent: requests.length,
                compared: 0,
                differing: 0,
            };
            rows.push(row);
            for (const request of requests) {
                const answers = active.map((runner) => ({
                    name: runner.spec.name,
                    line: runner.lines.get(request.id),
                }));
                const missing = answers.filter((answer) => answer.line === undefined);
                if (missing.length > 0) {
                    failures.push(`${request.id}: no answer from ${missing.map((m) => m.name).join(', ')}`);
                    row.differing += 1;
                    continue;
                }
                if (active.length < 2) continue;
                row.compared += 1;
                const parsed = answers.map((answer) => ({
                    name: answer.name,
                    ...(parse(answer.line) as Parsed),
                }));
                const [reference, ...others] = parsed as [
                    Parsed & { name: string },
                    ...Array<Parsed & { name: string }>,
                ];
                const bad = others.filter(
                    (other) => other.out !== reference.out || other.counts !== reference.counts,
                );
                if (bad.length === 0) continue;
                row.differing += 1;
                if (failures.length >= show) continue;
                const item = byId.get(request.id.split('|')[0] as string) as DiffCase;
                const detail = parsed
                    .map((p) => `    ${p.name}: ${clip(p.out)}  hits ${p.counts}`)
                    .join('\n');
                failures.push(
                    `${request.id} [${item.family}] input ${clip(JSON.stringify(request.input))}\n${detail}`,
                );
            }
        }
    }
    return { rows, failures };
}

function printTable(rows: Row[], runners: Runner[]): void {
    const names = runners.map((runner) => runner.spec.name);
    const header = ['tier', 'mode', ...names.map((name) => `${name} cases`), 'compared', 'differing'];
    const lines = rows.map((row) => [
        row.tier,
        row.mode,
        ...names.map((name) => (row.runners.includes(name) ? String(row.sent) : 'skipped')),
        row.compared === 0 ? 'only one runner' : String(row.compared),
        String(row.differing),
    ]);
    const widths = header.map((cell, i) =>
        Math.max(cell.length, ...lines.map((line) => (line[i] as string).length)),
    );
    const format = (cells: string[]): string =>
        cells.map((cell, i) => cell.padEnd(widths[i] as number)).join('  ');
    console.log([format(header), format(widths.map((w) => '-'.repeat(w))), ...lines.map(format)].join('\n'));
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const option = (name: string, fallback: string): string => {
        const index = args.indexOf(name);
        return index === -1 ? fallback : (args[index + 1] as string);
    };
    const only = option('--only', 'ts,python,go').split(',');
    const show = Number(option('--show', '10'));
    const limit = Number(option('--limit', '0'));
    const work = mkdtempSync(join(tmpdir(), 'redaction-diff-'));
    const deadline = setTimeout(() => {
        console.error('differential run exceeded its deadline');
        process.exit(1);
    }, DEADLINE_MS);
    try {
        const all = allCases();
        const cases = limit > 0 ? all.slice(0, limit) : all;
        if (limit === 0 && cases.length < MIN_CASES) throw new Error(`only ${cases.length} cases`);
        const runners = runnerSpecs(only, work).map((spec) => new Runner(spec));
        for (const runner of runners) await runner.capabilitiesLine();
        await Promise.all(
            runners.map(async (runner) => {
                const requests = TIERS.flatMap((tier) =>
                    MODES.filter((mode) => runner.capabilities[tier]?.includes(mode)).flatMap((mode) =>
                        requestsFor(cases, tier, mode),
                    ),
                );
                await runner.send(requests);
                await runner.finish();
            }),
        );
        const { rows, failures } = compare(runners, cases, show);
        console.log(`differential: ${cases.length} cases, runners ${only.join(', ')}`);
        for (const runner of runners)
            console.log(`  ${runner.spec.name}: ${JSON.stringify(runner.capabilities)}`);
        printTable(rows, runners);
        const differing = rows.reduce((sum, row) => sum + row.differing, 0);
        if (differing > 0) {
            console.error(`\n${differing} difference(s); first ${failures.length}:\n${failures.join('\n')}`);
            process.exit(1);
        }
        console.log('\nno differences');
    } finally {
        clearTimeout(deadline);
        rmSync(work, { recursive: true, force: true });
    }
}

await main();
