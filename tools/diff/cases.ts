/**
 * The cases of the differential test, all seeded and deterministic: the golden corpus families
 * (tools/corpus), the inputs of every spec vector file, the upstream secretlint fixtures, the attack
 * units of the scaling test at small sizes, and a differential family of random mixes of all of those
 * with astral characters and lone surrogates.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { CONTEXTS, jsonValue, marker, NEUTRAL_KEYS, SECRET_KEYS, WORDS } from '../corpus/families.ts';
import { generateCorpus } from '../corpus/generate.ts';
import { vectorInputs } from '../corpus/record.ts';
import { mulberry32, pick, type Rng } from '../corpus/rng.ts';
import { FORMAT_SAMPLES, SCANNER_SAMPLES } from '../corpus/samples.ts';
import { caseInput, type CaseOpts } from '../corpus/types.ts';
import { attacksFor, attackText } from '../lib/attacks.ts';
import { readSpecDir } from '../lib/spec-patterns.ts';
import type { Kind, Mode, RequestOpts } from './protocol.ts';

const ROOT = resolve(import.meta.dir, '..', '..');
const SPEC = join(ROOT, 'spec');
/** A text longer than this (UTF-16 units) is left out: the big cap cases are in the golden replays. */
const MAX_UNITS = 300_000;
const MIX_CASES = 3000;
const MIX_SEED = 0xd1ff3;
const ATTACK_SIZES = [2_000, 20_000];

export type DiffCase = {
    id: string;
    family: string;
    kind: Kind;
    input: unknown;
    opts: RequestOpts;
    /** Only these modes (a vector case names its mode); default both. */
    modes?: Mode[];
};

function requestOpts(opts: CaseOpts | undefined): RequestOpts {
    return opts === undefined ? {} : { ...opts };
}

function kindOf(input: unknown): Kind {
    return typeof input === 'string' ? 'text' : 'json';
}

function tooLong(input: unknown): boolean {
    return typeof input === 'string' && input.length > MAX_UNITS;
}

function corpusCases(): DiffCase[] {
    const inputs = vectorInputs(join(SPEC, 'vectors'));
    return generateCorpus(inputs).flatMap((item) => {
        const input = caseInput(item);
        if (tooLong(input)) return [];
        return [
            { id: item.id, family: item.family, kind: kindOf(input), input, opts: requestOpts(item.opts) },
        ];
    });
}

type VectorCase = { name: string; input?: unknown; inputGen?: { parts: Array<[string, number]> } } & {
    mode?: Mode;
    opts?: RequestOpts;
};

/** The vector cases that set a mode, limits or a generated input (the plain ones are corpus cases). */
function vectorCases(): DiffCase[] {
    const cases: DiffCase[] = [];
    for (const name of readdirSync(join(SPEC, 'vectors'))
        .filter((file) => file.endsWith('.json'))
        .sort()) {
        const parsed = JSON.parse(readFileSync(join(SPEC, 'vectors', name), 'utf8')) as {
            cases: VectorCase[];
        };
        parsed.cases.forEach((item, index) => {
            const special = item.mode !== undefined || item.opts !== undefined || item.inputGen !== undefined;
            if (!special) return;
            const input = item.inputGen === undefined ? item.input : expand(item.inputGen.parts);
            if (tooLong(input)) return;
            const modes: Mode[] = [item.mode ?? 'compat'];
            const id = `${name.replace(/\.json$/, '')}-${index}`;
            cases.push({
                id,
                family: 'vector-mode',
                kind: kindOf(input),
                input,
                opts: item.opts ?? {},
                modes,
            });
        });
    }
    return cases;
}

function expand(parts: Array<[string, number]>): string {
    return parts.map(([unit, times]) => unit.repeat(times)).join('');
}

/** Names of the case directories (`ng.*` positive, `ok.*` negative) holding an upstream fixture input. */
const FIXTURE_DIR = /^(ng|ok)\./;
const FIXTURE_INPUT = /^input/;

/** The `input*` file of every `ng.*` and `ok.*` case directory of the secretlint fixtures. */
function fixtureCases(): DiffCase[] {
    const base = join(SPEC, 'corpus', 'secretlint-13.0.4');
    const cases: DiffCase[] = [];
    for (const rule of readdirSync(base).sort()) {
        const ruleDir = join(base, rule);
        if (!statSync(ruleDir).isDirectory()) continue;
        for (const name of readdirSync(ruleDir).sort()) {
            const caseDir = join(ruleDir, name);
            if (!FIXTURE_DIR.test(name) || !statSync(caseDir).isDirectory()) continue;
            for (const file of readdirSync(caseDir).sort()) {
                const path = join(caseDir, file);
                if (!FIXTURE_INPUT.test(file) || !statSync(path).isFile()) continue;
                if (statSync(path).size > MAX_UNITS) continue;
                const text = readFileSync(path, 'utf8');
                const id = `${rule}/${name}/${file}`;
                cases.push({ id, family: 'secretlint-fixture', kind: 'text', input: text, opts: {} });
                cases.push({
                    id: `${id}#json`,
                    family: 'secretlint-fixture',
                    kind: 'json',
                    input: { log: text },
                    opts: {},
                });
            }
        }
    }
    return cases;
}

function attackCases(): DiffCase[] {
    const cases: DiffCase[] = [];
    attacksFor(readSpecDir(SPEC)).forEach((attack, index) => {
        for (const size of ATTACK_SIZES) {
            const text = attackText(attack, size);
            cases.push({
                id: `attack-${index}-${size}`,
                family: 'attack',
                kind: 'text',
                input: text,
                opts: {},
            });
        }
        cases.push({
            id: `attack-${index}-json`,
            family: 'attack',
            kind: 'json',
            input: { body: attackText(attack, 2_000), password: 'Zq9abcDEF123ghi_x' },
            opts: {},
        });
    });
    return cases;
}

const ASTRAL = [
    '\u{1f600}',
    '\u{1f511}',
    '\u{10ffff}',
    '\ud83d',
    '\ude00',
    '\ud800\ud800',
    'é',
    'é',
    'K',
    '﻿',
];
const SEPARATORS = [' ', '\n', '\t', ' ', ' ', ' ', ', ', '="', '=', ': ', '&', '?', '\\"', '"'];

function pieces(rng: Rng): string[] {
    const attacks = attacksFor(readSpecDir(SPEC)).map((attack) => attack.unit);
    return [
        ...FORMAT_SAMPLES,
        ...SCANNER_SAMPLES,
        ...attacks,
        ...WORDS,
        ...ASTRAL,
        ...CONTEXTS.map((context) => context(marker(rng))),
    ];
}

function mixText(rng: Rng, parts: readonly string[]): string {
    const count = 2 + Math.floor(rng() * 11);
    let text = '';
    for (let i = 0; i < count; i++) text += pick(rng, parts) + pick(rng, SEPARATORS);
    return text;
}

/** Random mixes: free text, text in a JSON value under secret and neutral keys, and generated JSON values. */
function mixCases(): DiffCase[] {
    const rng = mulberry32(MIX_SEED);
    const parts = pieces(rng);
    const keys = [...SECRET_KEYS, ...NEUTRAL_KEYS];
    const cases: DiffCase[] = [];
    for (let i = 0; i < MIX_CASES; i++) {
        const roll = rng();
        if (roll < 0.45) {
            cases.push({
                id: `mix-${i}`,
                family: 'mix-text',
                kind: 'text',
                input: mixText(rng, parts),
                opts: {},
            });
        } else if (roll < 0.8) {
            const input = {
                [pick(rng, keys)]: mixText(rng, parts),
                [pick(rng, keys)]: [mixText(rng, parts)],
            };
            cases.push({ id: `mix-${i}`, family: 'mix-json', kind: 'json', input, opts: {} });
        } else {
            cases.push({
                id: `mix-${i}`,
                family: 'mix-value',
                kind: 'json',
                input: jsonValue(rng, 4),
                opts: {},
            });
        }
    }
    return cases;
}

export function allCases(): DiffCase[] {
    const cases = [...corpusCases(), ...vectorCases(), ...fixtureCases(), ...attackCases(), ...mixCases()];
    const ids = new Set(cases.map((item) => item.id));
    if (ids.size !== cases.length) throw new Error('duplicate case ids');
    return cases;
}
