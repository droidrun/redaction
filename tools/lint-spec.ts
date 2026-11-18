#!/usr/bin/env bun
/**
 * lint-spec — checks the spec (SPEC.md section 11):
 *   1. JSON Schema validation of rules/keys/algorithms and every vector file;
 *   2. the portable grammar ban list and the rule-id pattern, on every expanded pattern;
 *   3. recheck (static ReDoS analysis): anything but "safe" fails;
 *   4. every pattern compiles in JS, Python (re.ASCII) and Go (regexp);
 *   5. scaling: attack strings at 100 KB and 1 MB run in JS and Python with near-linear time.
 *
 *   bun tools/lint-spec.ts [--spec-dir DIR] [--skip-scaling] [--skip-recheck] [--self-test]
 * `--self-test` plants a lookbehind, a `\s`, a `{0,1024}` and a nested quantifier and fails
 * unless every one of them is reported.
 */
import Ajv from 'ajv';
import { check } from 'recheck';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { attacksFor } from './lib/attacks.ts';
import { grammarViolations, ruleIdViolation } from './lib/grammar.ts';
import { collectPatterns, readSpecDir, type NamedPattern } from './lib/spec-patterns.ts';

const ROOT = resolve(import.meta.dir, '..');
const SIZES = [100_000, 1_000_000];
const MAX_RATIO = 30;
const NOISE_FLOOR_MS = 10;
const MAX_MS_AT_LARGE = 3000;
const SCALING_DEADLINE_MS = 900_000;

type Problem = string;

function validateSchemas(dir: string, schemaDir: string): Problem[] {
    const ajv = new Ajv({ allErrors: true, strict: false });
    const problems: Problem[] = [];
    const read = (path: string): unknown => JSON.parse(readFileSync(path, 'utf8'));
    for (const name of ['rules', 'keys', 'algorithms']) {
        const validate = ajv.compile(read(join(schemaDir, `${name}.schema.json`)) as object);
        if (!validate(read(join(dir, `${name}.json`)))) {
            for (const error of validate.errors ?? [])
                problems.push(`${name}.json${error.instancePath}: ${error.message}`);
        }
    }
    const validateVector = ajv.compile(read(join(schemaDir, 'vectors.schema.json')) as object);
    for (const file of readdirSync(join(dir, 'vectors'))
        .filter((name) => name.endsWith('.json'))
        .sort()) {
        const parsed = read(join(dir, 'vectors', file)) as { cases: Array<{ name: string }> };
        if (!validateVector(parsed)) {
            for (const error of validateVector.errors ?? [])
                problems.push(`vectors/${file}${error.instancePath}: ${error.message}`);
        }
        const names = parsed.cases.map((item) => item.name);
        if (new Set(names).size !== names.length) problems.push(`vectors/${file}: duplicate case names`);
    }
    return problems;
}

function ruleIdProblems(dir: string): Problem[] {
    const spec = readSpecDir(dir);
    const ids = [
        ...spec.rules.pipeline.map((rule) => String(rule.id)),
        ...Object.values((spec.algorithms as { ruleIds: Record<string, string> }).ruleIds),
    ];
    return ids.flatMap((id) => ruleIdViolation(id) ?? []);
}

function grammarProblems(patterns: NamedPattern[]): Problem[] {
    return patterns.flatMap((pattern) => {
        return grammarViolations(pattern.source).map((violation) => `${pattern.where}: ${violation}`);
    });
}

async function recheckProblems(patterns: NamedPattern[]): Promise<Problem[]> {
    const problems: Problem[] = [];
    for (const pattern of patterns.filter((item) => item.role === 'pattern')) {
        const result = await check(pattern.source, '', { timeout: 60_000 } as never);
        if (result.status !== 'safe') problems.push(`${pattern.where}: recheck says ${result.status}`);
    }
    return problems;
}

function jsCompileProblems(patterns: NamedPattern[]): Problem[] {
    return patterns.flatMap((pattern) => {
        try {
            new RegExp(pattern.source);
            return [];
        } catch {
            return [`${pattern.where}: does not compile in JavaScript`];
        }
    });
}

function runChecker(
    command: string,
    args: string[],
    cwd: string,
    patterns: NamedPattern[],
    label: string,
): Problem[] {
    const input = JSON.stringify(patterns.map(({ where, source }) => ({ where, source })));
    const result = spawnSync(command, args, { cwd, input, encoding: 'utf8', timeout: 120_000 });
    if (result.status !== 0) return [`${label} checker failed to run: ${result.stderr.slice(0, 200)}`];
    const failures = JSON.parse(result.stdout) as Array<{ where: string; error: string }>;
    return failures.map((failure) => `${failure.where}: does not compile in ${label} (${failure.error})`);
}

type Timing = { where: string; attack: string; size: number; ms: number };

function scalingProblems(patterns: NamedPattern[], dir: string): Problem[] {
    const attacks = attacksFor(readSpecDir(dir));
    const payload = JSON.stringify({
        patterns: patterns
            .filter((item) => item.role === 'pattern')
            .map(({ where, source }) => ({ where, source })),
        attacks,
        sizes: SIZES,
        runs: 2,
    });
    const problems: Problem[] = [];
    const runners: Array<[string, string, string[]]> = [
        ['JavaScript', 'bun', [join(ROOT, 'tools/lint/scaling.ts')]],
        ['Python', 'python3', ['-I', join(ROOT, 'tools/lint/scaling.py')]],
    ];
    for (const [label, command, args] of runners) {
        const result = spawnSync(command, args, {
            input: payload,
            encoding: 'utf8',
            timeout: SCALING_DEADLINE_MS,
            maxBuffer: 256 * 1024 * 1024,
        });
        if (result.status !== 0) {
            problems.push(`${label} scaling run did not finish (deadline or crash)`);
            continue;
        }
        const byKey = new Map<string, Record<number, number>>();
        for (const timing of JSON.parse(result.stdout) as Timing[]) {
            const key = `${timing.where} | ${timing.attack}`;
            byKey.set(key, { ...(byKey.get(key) ?? {}), [timing.size]: timing.ms });
        }
        for (const [key, times] of byKey) {
            const small = Math.max(times[SIZES[0] as number] ?? 0, NOISE_FLOOR_MS);
            const large = times[SIZES[1] as number] ?? 0;
            if (large > small * MAX_RATIO || large > MAX_MS_AT_LARGE) {
                problems.push(
                    `${label} scaling: ${key}: ${Math.round(small)} ms at 100 KB, ` +
                        `${Math.round(large)} ms at 1 MB`,
                );
            }
        }
    }
    return problems;
}

function patternsFor(dir: string): NamedPattern[] {
    return collectPatterns(readSpecDir(dir));
}

export async function lintDir(
    dir: string,
    options: { scaling: boolean; recheck: boolean },
): Promise<Problem[]> {
    const schemaDir = join(ROOT, 'spec', 'schema');
    const patterns = patternsFor(dir);
    const problems = [
        ...validateSchemas(dir, schemaDir),
        ...ruleIdProblems(dir),
        ...grammarProblems(patterns),
        ...jsCompileProblems(patterns),
        ...runChecker('python3', ['-I', join(ROOT, 'tools/lint/compile.py')], ROOT, patterns, 'Python'),
        ...runChecker('go', ['run', '.'], join(ROOT, 'tools/lint/gocheck'), patterns, 'Go'),
    ];
    if (options.recheck) problems.push(...(await recheckProblems(patterns)));
    if (options.scaling) problems.push(...scalingProblems(patterns, dir));
    return problems;
}

/** Patterns a portable spec must reject; each must be reported by the grammar or by recheck. */
const PLANTED: Array<[name: string, source: string]> = [
    ['lookbehind', '(?<!a)b[a-z]{3}'],
    ['\\s shorthand', 'a\\s+b'],
    ['bound {0,1024}', 'a[b-c]{0,1024}'],
    ['nested quantifier', '(a+)+b'],
];

async function selfTest(): Promise<Problem[]> {
    const problems: Problem[] = [];
    for (const [name, source] of PLANTED) {
        const found = grammarViolations(source);
        const vulnerable = name === 'nested quantifier' && (await check(source, '')).status === 'vulnerable';
        if (found.length === 0 && !vulnerable)
            problems.push(`self-test: the planted ${name} was not reported`);
    }
    const copy = mkdtempSync(join(tmpdir(), 'lint-spec-'));
    try {
        cpSync(join(ROOT, 'spec'), copy, { recursive: true });
        const rulesPath = join(copy, 'rules.json');
        const rules = JSON.parse(readFileSync(rulesPath, 'utf8')) as {
            pipeline: Array<Record<string, unknown>>;
        };
        const target = rules.pipeline.find((rule) => rule.id === 'xai-api-key') as Record<string, unknown>;
        target.pattern = '(?<![a-z])xai-[0-9a-zA-Z_]{80}\\b';
        writeFileSync(rulesPath, JSON.stringify(rules, null, 2));
        const planted = await lintDir(copy, { scaling: false, recheck: false });
        if (!planted.some((problem) => problem.includes('lookaround'))) {
            problems.push('self-test: a lookbehind planted in rules.json did not fail the lint');
        }
    } finally {
        rmSync(copy, { recursive: true, force: true });
    }
    return problems;
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const dirIndex = args.indexOf('--spec-dir');
    const dir = dirIndex === -1 ? join(ROOT, 'spec') : resolve(args[dirIndex + 1] as string);
    const problems = args.includes('--self-test')
        ? await selfTest()
        : await lintDir(dir, {
              scaling: !args.includes('--skip-scaling'),
              recheck: !args.includes('--skip-recheck'),
          });
    if (problems.length > 0) {
        console.error(problems.join('\n'));
        console.error(`lint-spec: ${problems.length} problem(s)`);
        process.exit(1);
    }
    console.log(args.includes('--self-test') ? 'lint-spec self-test: ok' : 'lint-spec: ok');
}

if (import.meta.main) await main();
