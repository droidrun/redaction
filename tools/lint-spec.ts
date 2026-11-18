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
import {
    classShapeViolation,
    emptyMatchViolation,
    grammarViolations,
    ruleIdViolation,
} from './lib/grammar.ts';
import {
    collectPatterns,
    readSpecDir,
    RULE_LISTS,
    unclassifiedFields,
    type NamedPattern,
} from './lib/spec-patterns.ts';
import { tokenShapeProblems } from './lib/token-shape.ts';

const ROOT = resolve(import.meta.dir, '..');
const SIZES = [100_000, 1_000_000];
const MAX_RATIO = 30;
const NOISE_FLOOR_MS = 10;
const MAX_MS_AT_LARGE = 3000;
const MAX_INTERPRETER_MS_AT_LARGE = 10_000;
/** A composite attack (short cluster, long run) may cost at most this many times the plain text of its size. */
const MAX_COMPOSITE_FACTOR = 20;
const COMPOSITE_FLOOR_MS = 20;
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

/** A `regex` rule takes a capture `group` or guards, never both (SPEC 4.1: guarded matches are whole). */
function ruleShapeProblems(dir: string): Problem[] {
    const rules = readSpecDir(dir).rules;
    return RULE_LISTS.flatMap((list) =>
        rules[list].flatMap((rule, index) => {
            const hasGuard = rule.notBefore !== undefined || rule.notAfter !== undefined;
            const hasGroup = rule.group !== undefined && rule.group !== 0;
            if (rule.kind !== 'regex' || !hasGuard || !hasGroup) return [];
            return [
                `${list}[${index}] ${String(rule.id)}: group combined with guards (SPEC 4.1 allows one of them)`,
            ];
        }),
    );
}

function ruleIdProblems(dir: string): Problem[] {
    const spec = readSpecDir(dir);
    const ids = [
        ...spec.rules.pipeline.map((rule) => String(rule.id)),
        ...spec.rules.full.map((rule) => String(rule.id)),
        ...Object.values((spec.algorithms as { ruleIds: Record<string, string> }).ruleIds),
    ];
    return ids.flatMap((id) => ruleIdViolation(id) ?? []);
}

function grammarProblems(patterns: NamedPattern[]): Problem[] {
    return patterns.flatMap((pattern) => {
        const found = grammarViolations(pattern.source);
        const shape = pattern.role === 'class' ? classShapeViolation(pattern.source) : undefined;
        const empty = pattern.role === 'pattern' ? emptyMatchViolation(pattern.source) : undefined;
        return [...found, ...(shape ? [shape] : []), ...(empty ? [empty] : [])].map(
            (violation) => `${pattern.where}: ${violation}`,
        );
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

/** Scaling through `detectSyncHits` and `detectFullHits` of the TypeScript package: the restart loops of every rule kind. */
export function interpreterScalingProblems(dir: string): Problem[] {
    const attacks = attacksFor(readSpecDir(dir));
    const payload = JSON.stringify({ attacks, sizes: SIZES });
    const result = spawnSync('bun', [join(ROOT, 'tools/lint/scaling-interpreter.ts')], {
        input: payload,
        encoding: 'utf8',
        timeout: SCALING_DEADLINE_MS,
        maxBuffer: 256 * 1024 * 1024,
    });
    if (result.status !== 0) return ['interpreter scaling run did not finish (deadline or crash)'];
    const byAttack = new Map<string, Record<number, number>>();
    for (const timing of JSON.parse(result.stdout) as Timing[]) {
        byAttack.set(timing.attack, { ...(byAttack.get(timing.attack) ?? {}), [timing.size]: timing.ms });
    }
    const problems: Problem[] = [];
    const composites = new Set(
        attacks.filter((attack) => attack.head !== undefined).map((attack) => attack.name),
    );
    const plain = Math.max(byAttack.get('__plain')?.[SIZES[1] as number] ?? 0, COMPOSITE_FLOOR_MS);
    for (const [attack, times] of byAttack) {
        const small = Math.max(times[SIZES[0] as number] ?? 0, NOISE_FLOOR_MS);
        const large = times[SIZES[1] as number] ?? 0;
        if (composites.has(attack) && large > plain * MAX_COMPOSITE_FACTOR) {
            problems.push(
                `interpreter scaling: ${attack}: ${Math.round(large)} ms at 1 MB, more than ` +
                    `${MAX_COMPOSITE_FACTOR} times the plain text (${Math.round(plain)} ms): a long run is measured again per start`,
            );
        }
        if (large > small * MAX_RATIO || large > MAX_INTERPRETER_MS_AT_LARGE) {
            problems.push(
                `interpreter scaling: ${attack}: ${Math.round(small)} ms at 100 KB, ` +
                    `${Math.round(large)} ms at 1 MB`,
            );
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
        ...ruleShapeProblems(dir),
        ...tokenShapeProblems(readSpecDir(dir)),
        ...unclassifiedFields(readSpecDir(dir)),
        ...grammarProblems(patterns),
        ...jsCompileProblems(patterns),
        ...runChecker('python3', ['-I', join(ROOT, 'tools/lint/compile.py')], ROOT, patterns, 'Python'),
        ...runChecker('go', ['run', '.'], join(ROOT, 'tools/lint/gocheck'), patterns, 'Go'),
    ];
    if (options.recheck) problems.push(...(await recheckProblems(patterns)));
    if (options.scaling) problems.push(...scalingProblems(patterns, dir), ...interpreterScalingProblems(dir));
    return problems;
}

type Plant = {
    name: string;
    rule: string;
    field: string;
    value: unknown;
    expect: string;
    list?: 'pipeline' | 'full';
};

/** Each plant is written into a rule of a copy of the spec; the lint must report it. */
const PLANTS: Plant[] = [
    {
        name: 'lookbehind',
        rule: 'xai-api-key',
        field: 'pattern',
        value: '(?<![a-z])xai-[0-9a-zA-Z_]{80}',
        expect: 'lookaround',
    },
    {
        name: '\\s shorthand',
        rule: 'xai-api-key',
        field: 'pattern',
        value: 'xai-\\s[0-9a-zA-Z_]{80}',
        expect: 'shorthand class',
    },
    {
        name: 'bound {0,1024}',
        rule: 'xai-api-key',
        field: 'pattern',
        value: 'xai-[0-9a-zA-Z_]{0,1024}',
        expect: 'above 1000',
    },
    {
        name: 'nested quantifier',
        rule: 'xai-api-key',
        field: 'pattern',
        value: '(?:a+)+xai-[0-9]{80}',
        expect: 'nested quantifier',
    },
    {
        name: '\\w in segmentClass',
        rule: 'jwt',
        field: 'segmentClass',
        value: '\\w',
        expect: 'shorthand class',
    },
    {
        name: '\\w in segmentClass (shape)',
        rule: 'jwt',
        field: 'segmentClass',
        value: '\\w',
        expect: 'single character class',
    },
    {
        name: 'alternation in a class field',
        rule: 'openai',
        field: 'requireClass',
        value: '(?:a|aa)+b',
        expect: 'single character class',
    },
    {
        name: 'class followed by text',
        rule: 'openai',
        field: 'requireClass',
        value: '[0-9]x',
        expect: 'single character class',
    },
    {
        name: 'class starting with ]',
        rule: 'xai-api-key',
        field: 'pattern',
        value: 'xai-[]a]{80}',
        expect: 'starts with "]"',
    },
    {
        name: 'negated class starting with ]',
        rule: 'xai-api-key',
        field: 'pattern',
        value: 'xai-[^]a]{80}',
        expect: 'starts with "]"',
    },
    {
        name: '\\B context-sensitive',
        rule: 'xai-api-key',
        field: 'pattern',
        value: 'xai-\\B[0-9a-zA-Z_]{80}',
        expect: 'context-sensitive',
    },
    {
        name: '\\A anchor escape',
        rule: 'xai-api-key',
        field: 'pattern',
        value: '\\Axai-[0-9a-zA-Z_]{80}',
        expect: 'context-sensitive',
    },
    {
        name: '\\Z anchor escape',
        rule: 'xai-api-key',
        field: 'pattern',
        value: 'xai-[0-9a-zA-Z_]{80}\\Z',
        expect: 'context-sensitive',
    },
    {
        name: 'group with guards',
        rule: 'gcp-api-key',
        field: 'group',
        value: 1,
        expect: 'group combined with guards',
    },
    {
        name: 'astral literal',
        rule: 'xai-api-key',
        field: 'pattern',
        value: 'xai-[\u{1F600}a]{80}',
        expect: 'surrogate unit',
    },
    {
        name: 'lone surrogate',
        rule: 'xai-api-key',
        field: 'pattern',
        value: 'xai-[\ud83d]{80}',
        expect: 'surrogate unit',
    },
    {
        name: 'empty match',
        rule: 'xai-api-key',
        field: 'pattern',
        value: '(?:xai-[0-9]{80})?',
        expect: 'empty string',
    },
    {
        name: 'unknown string field',
        rule: 'xai-api-key',
        field: 'mystery',
        value: '(?<!a)b',
        expect: 'cannot classify',
    },
    // The full tier: the same checks reach its rules, and its token shapes have their own conditions.
    {
        name: 'lookbehind in a full-tier pattern',
        list: 'full',
        rule: 'openai',
        field: 'pattern',
        value: '(?<![a-z])sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}',
        expect: 'lookaround',
    },
    {
        name: 'unknown string field inside a token part',
        list: 'full',
        rule: 'gitlab',
        field: 'parts',
        value: [
            { lit: 'glpat-', mystery: '(?<!a)b' },
            { runClass: '[A-Za-z0-9_-]', min: 20, max: 128 },
        ],
        expect: 'cannot classify',
    },
    {
        name: 'variable run followed by a unit of its own class',
        list: 'full',
        rule: 'gitlab',
        field: 'parts',
        value: [{ lit: 'glpat-' }, { runClass: '[A-Za-z0-9_-]', min: 20, max: 128 }, { lit: 'a' }],
        expect: 'starts with a unit of its class',
    },
    {
        name: 'variable run at the end without notAfter',
        list: 'full',
        rule: 'gitlab',
        field: 'notAfter',
        value: undefined,
        expect: 'without notAfter',
    },
    {
        name: 'notAfter that does not cover the variable run',
        list: 'full',
        rule: 'gitlab',
        field: 'notAfter',
        value: '[a-z]',
        expect: 'does not cover',
    },
    {
        name: 'alternative that is a prefix of another',
        list: 'full',
        rule: 'vercel',
        field: 'parts',
        value: [{ alt: ['vc', 'vcp'] }, { lit: '_' }, { runClass: '[A-Za-z0-9]', min: 20, max: 60 }],
        expect: 'prefix of another',
    },
    {
        name: 'tail with a unit outside the run class',
        list: 'full',
        rule: 'anthropic',
        field: 'parts',
        value: [{ lit: 'sk-ant-api0' }, { runClass: '[A-Za-z0-9_-]', min: 90, max: 128, tails: ['A!'] }],
        expect: 'outside the class',
    },
];

function lintPlanted(plant: Plant): Promise<Problem[]> {
    const copy = mkdtempSync(join(tmpdir(), 'lint-spec-'));
    try {
        cpSync(join(ROOT, 'spec'), copy, { recursive: true });
        const rulesPath = join(copy, 'rules.json');
        const rules = JSON.parse(readFileSync(rulesPath, 'utf8')) as Record<
            string,
            Array<Record<string, unknown>>
        >;
        const target = (rules[plant.list ?? 'pipeline'] as Array<Record<string, unknown>>).find(
            (rule) => rule.id === plant.rule,
        ) as Record<string, unknown>;
        target[plant.field] = plant.value;
        writeFileSync(rulesPath, JSON.stringify(rules, null, 2));
        return lintDir(copy, { scaling: false, recheck: false });
    } finally {
        rmSync(copy, { recursive: true, force: true });
    }
}

async function selfTest(): Promise<Problem[]> {
    const problems: Problem[] = [];
    for (const plant of PLANTS) {
        const found = await lintPlanted(plant);
        if (!found.some((problem) => problem.includes(plant.expect))) {
            problems.push(`self-test: the planted ${plant.name} was not reported as "${plant.expect}"`);
        }
    }
    const unplanted = await lintDir(join(ROOT, 'spec'), { scaling: false, recheck: false });
    if (unplanted.length > 0) problems.push('self-test: the unmodified spec does not lint clean');
    const vulnerable = (await check('(a+)+b', '')).status === 'vulnerable';
    if (!vulnerable) problems.push('self-test: recheck did not flag (a+)+b');
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
