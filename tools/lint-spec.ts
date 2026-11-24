#!/usr/bin/env bun
/**
 * lint-spec — checks the spec (SPEC.md section 11):
 *   1. JSON Schema validation of rules/keys/algorithms and every vector file;
 *   2. the portable grammar ban list and the rule-id pattern, on every expanded pattern;
 *   3. recheck (static ReDoS analysis): anything but "safe" fails, unless the attack string it produced does
 *      not grow super-linearly in the scaling harness (then a warning with the attack; lib/recheck-gate.ts);
 *   4. every pattern compiles in JS, Python (re.ASCII) and Go (regexp);
 *   5. scaling: attack strings at 100 KB and 1 MB run in JS and Python with near-linear time.
 *
 *   bun tools/lint-spec.ts [--spec-dir DIR] [--skip-scaling] [--skip-recheck] [--self-test]
 *                          [--only ID,KIND,...] [--only-scaling] [--no-cache]
 * `--only` is the loop for rule work: schemas and rule checks always run, the pattern stages (grammar, compile,
 * recheck, scaling) only for the patterns of the named rule ids or kinds. The full run stays the gate.
 * `--only-scaling` runs just the scaling stages (CI runs them in their own job). The recheck verdicts are
 * cached in tools/.cache (a changed pattern misses); `--no-cache` analyses every pattern again.
 * `--self-test` plants a lookbehind, a `\s`, a `{0,1024}` and a nested quantifier and fails
 * unless every one of them is reported.
 */
import Ajv from 'ajv';
import { check } from 'recheck';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { FileGateCache, type GateCache } from './lib/recheck-cache.ts';
import { cachedRecheckGate, recheckGate } from './lib/recheck-gate.ts';
import { scalingProblems } from './lib/scaling-run.ts';
import { scopeFor, unknownOnly, type Scope } from './lib/selection.ts';
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
const CACHE_FILE = join(ROOT, 'tools', '.cache', 'recheck-gate.json');

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

/** The rule ids a strict edit names: the one it targets and the one of the rule it adds. */
function strictEditIds(edit: Record<string, unknown>): string[] {
    const added = edit.add as { id: string } | undefined;
    return [edit.id, added?.id].filter((id): id is string => typeof id === 'string');
}

/** Every `strict` edit must match at least one rule of the list it edits, and one that adds a rule exactly
 *  one (SPEC 4.10); the edits are applied in order, so a later edit sees the rules an earlier one added. */
function strictEditProblems(dir: string): Problem[] {
    const spec = readSpecDir(dir);
    let rules = [...spec.rules.pipeline];
    return spec.rules.strict.flatMap((edit, index) => {
        const targets = rules.filter((rule) => {
            const isId = edit.id === undefined || rule.id === edit.id;
            return isId && (edit.kind === undefined || rule.kind === edit.kind);
        });
        if (edit.add !== undefined && targets.length === 1) {
            const at = rules.indexOf(targets[0] as Record<string, unknown>);
            rules = [...rules.slice(0, at + 1), edit.add as Record<string, unknown>, ...rules.slice(at + 1)];
        }
        if (targets.length === 0) return [`strict[${index}]: the edit matches no rule`];
        const addsToMany = edit.add !== undefined && targets.length !== 1;
        return addsToMany ? [`strict[${index}]: an edit that adds a rule must match exactly one rule`] : [];
    });
}

function ruleIdProblems(dir: string): Problem[] {
    const spec = readSpecDir(dir);
    const ids = [
        ...spec.rules.pipeline.map((rule) => String(rule.id)),
        ...spec.rules.pii.map((rule) => String(rule.id)),
        ...spec.rules.strict.flatMap((edit) => strictEditIds(edit)),
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

async function recheckProblems(
    patterns: NamedPattern[],
    cache: GateCache | undefined,
): Promise<Problem[]> {
    const problems: Problem[] = [];
    for (const pattern of patterns.filter((item) => item.role === 'pattern')) {
        const gate = await cachedRecheckGate(pattern.where, pattern.source, cache);
        if (gate.warning !== undefined) console.warn(`WARNING ${gate.warning}`);
        if (gate.problem !== undefined) problems.push(gate.problem);
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

export type LintOptions = {
    scaling: boolean;
    recheck: boolean;
    /** Run only the scaling stages. */
    scalingOnly?: boolean;
    /** Rule ids or kinds the pattern stages are narrowed to. */
    only?: string[];
    cache?: GateCache;
};

async function patternProblemsFor(scope: Scope, options: LintOptions): Promise<Problem[]> {
    const { patterns } = scope;
    const problems = [
        ...grammarProblems(patterns),
        ...jsCompileProblems(patterns),
        ...runChecker('python3', ['-I', join(ROOT, 'tools/lint/compile.py')], ROOT, patterns, 'Python'),
        ...runChecker('go', ['run', '.'], join(ROOT, 'tools/lint/gocheck'), patterns, 'Go'),
    ];
    if (options.recheck) problems.push(...(await recheckProblems(patterns, options.cache)));
    if (options.scaling) problems.push(...(await scalingStage(scope)));
    return problems;
}

function scalingStage(scope: Scope): Promise<Problem[]> {
    const patterns = scope.patterns
        .filter((item) => item.role === 'pattern')
        .map(({ where, source }) => ({ where, source }));
    return scalingProblems(patterns, scope.attacks, scope.interpreterAttacks);
}

export async function lintDir(dir: string, options: LintOptions): Promise<Problem[]> {
    const spec = readSpecDir(dir);
    const all = collectPatterns(spec);
    const scope = scopeFor(spec, all, options.only);
    for (const line of scope.skipped) console.log(line);
    if (options.scalingOnly) return scalingStage(scope);
    const schemaDir = join(ROOT, 'spec', 'schema');
    const problems = [
        ...validateSchemas(dir, schemaDir),
        ...ruleIdProblems(dir),
        ...strictEditProblems(dir),
        ...ruleShapeProblems(dir),
        ...tokenShapeProblems(spec),
        ...unclassifiedFields(spec),
        ...(options.only === undefined ? [] : unknownOnly(all, options.only)),
    ];
    problems.push(...(await patternProblemsFor(scope, options)));
    return problems;
}

type Plant = {
    name: string;
    rule: string;
    field: string;
    value: unknown;
    expect: string;
    /** Further fields of the rule set with the planted one. */
    extra?: Record<string, unknown>;
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
        name: 'chained range [a-b-c] read as two ranges (the second hyphen is a unit)',
        list: 'full',
        rule: 'gitlab',
        field: 'parts',
        value: [{ lit: 'x' }, { runClass: '[a-b-c]', min: 1, max: 2 }],
        extra: { notAfter: '[a-c]' },
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
        Object.assign(target, plant.extra ?? {});
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
    // The gate: a real ReDoS without a nested group (grammar-clean) fails with its attack; a safe one passes.
    const real = await recheckGate('planted a*a*a*a*b', 'a*a*a*a*b');
    if (!real.problem?.includes('confirms it') || !real.problem.includes('attack')) {
        problems.push('self-test: a planted real ReDoS did not fail the recheck gate with its attack string');
    }
    const safe = await recheckGate('safe pattern', '[a-z]{1,8}x');
    if (safe.problem !== undefined || safe.warning !== undefined) {
        problems.push('self-test: a safe pattern did not pass the recheck gate');
    }
    return problems;
}

function optionValue(args: string[], name: string): string | undefined {
    const index = args.indexOf(name);
    return index === -1 ? undefined : args[index + 1];
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    const specDir = optionValue(args, '--spec-dir');
    const dir = specDir === undefined ? join(ROOT, 'spec') : resolve(specDir);
    const only = optionValue(args, '--only')?.split(',');
    const isSelfTest = args.includes('--self-test');
    const useCache = !args.includes('--no-cache') && !isSelfTest && specDir === undefined;
    const cache = useCache ? new FileGateCache(CACHE_FILE) : undefined;
    const problems = isSelfTest
        ? await selfTest()
        : await lintDir(dir, {
              scaling: !args.includes('--skip-scaling'),
              recheck: !args.includes('--skip-recheck'),
              scalingOnly: args.includes('--only-scaling'),
              only,
              cache,
          });
    cache?.save(only === undefined);
    if (problems.length > 0) {
        console.error(problems.join('\n'));
        console.error(`lint-spec: ${problems.length} problem(s)`);
        process.exit(1);
    }
    console.log(isSelfTest ? 'lint-spec self-test: ok' : 'lint-spec: ok');
}

if (import.meta.main) await main();
