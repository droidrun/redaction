/**
 * scaling-run — the scaling stages of lint-spec: the JavaScript and Python pattern runs and the interpreter run
 * start together (async subprocesses, each under its own deadline) and report their problems in a fixed order.
 * A measurement that would fail is repeated up to SCALING_RETRIES more times and the best time per size is used,
 * so a loaded machine does not fail a pattern that is linear; the thresholds are those of recheck-gate.ts.
 */
import { spawn } from 'node:child_process';
import { availableParallelism } from 'node:os';
import { join, resolve } from 'node:path';
import type { Attack } from './attacks.ts';
import {
    growthOfSizes,
    MAX_MS_AT_LARGE,
    MAX_RATIO,
    NOISE_FLOOR_MS,
    RUNNERS,
    SIZES,
    type Timing,
} from './recheck-gate.ts';

const ROOT = resolve(import.meta.dir, '..', '..');
const SCALING_DEADLINE_MS = 900_000;
const RETRY_DEADLINE_MS = 120_000;
export const SCALING_RETRIES = 2;
const MAX_INTERPRETER_MS_AT_LARGE = 10_000;
/** A composite attack (short cluster, long run) may cost at most this many times the plain text of its size. */
const MAX_COMPOSITE_FACTOR = 20;
const COMPOSITE_FLOOR_MS = 20;
/** The attack scaling-interpreter.ts adds to every run as the baseline of the composite attacks. */
const PLAIN_ATTACK = '__plain';
const MAX_BUFFER = 256 * 1024 * 1024;
/** Processes one pattern run is spread over: a run measures every pattern against every attack, one pattern
 *  after the other, so slices of the pattern list run side by side. */
const MAX_SHARDS = 4;

type Problem = string;
export type Sizes = Record<number, number>;
export type ScalingPattern = { where: string; source: string };

/** Runs a command with `input` on stdin; `status` is null when it was killed at the deadline or did not start. */
export function runAsync(
    command: string,
    args: string[],
    input: string,
    deadlineMs: number,
): Promise<{ status: number | null; stdout: string }> {
    return new Promise((done) => {
        const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'ignore'] });
        const chunks: Buffer[] = [];
        let size = 0;
        const timer = setTimeout(() => child.kill('SIGKILL'), deadlineMs);
        child.stdout.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_BUFFER) child.kill('SIGKILL');
            else chunks.push(chunk);
        });
        child.on('error', () => {
            clearTimeout(timer);
            done({ status: null, stdout: '' });
        });
        child.on('close', (status) => {
            clearTimeout(timer);
            done({ status, stdout: Buffer.concat(chunks).toString('utf8') });
        });
        child.stdin.on('error', () => undefined);
        child.stdin.end(input);
    });
}

/** The list in at most `count` consecutive slices of nearly equal size; their concatenation is the list. */
export function shardsOf<T>(items: T[], count: number): T[][] {
    const size = Math.max(1, Math.ceil(items.length / count));
    const shards: T[][] = [];
    for (let at = 0; at < items.length; at += size) shards.push(items.slice(at, at + size));
    return shards;
}

function bySizes(timings: Timing[], keyOf: (timing: Timing) => string): Map<string, Sizes> {
    const found = new Map<string, Sizes>();
    for (const timing of timings) {
        const key = keyOf(timing);
        found.set(key, { ...(found.get(key) ?? {}), [timing.size]: timing.ms });
    }
    return found;
}

/** The best (smallest) time per size of two measurements. */
function best(first: Sizes, second: Sizes): Sizes {
    return Object.fromEntries(
        SIZES.map((size) => [size, Math.min(first[size] ?? Infinity, second[size] ?? Infinity)]),
    );
}

/** Re-measures while `isSlow` holds, at most SCALING_RETRIES times; the best time per size wins. */
export async function bestOfRetries(
    first: Sizes,
    isSlow: (times: Sizes) => boolean,
    measure: () => Promise<Sizes | undefined>,
    report: (attempt: number, times: Sizes) => void,
): Promise<Sizes> {
    let times = first;
    for (let attempt = 1; attempt <= SCALING_RETRIES && isSlow(times); attempt++) {
        const again = await measure();
        if (again === undefined) continue;
        times = best(times, again);
        report(attempt, times);
    }
    return times;
}

async function measure(
    command: string,
    args: string[],
    payload: unknown,
    deadlineMs: number,
): Promise<Timing[] | undefined> {
    const result = await runAsync(command, args, JSON.stringify(payload), deadlineMs);
    return result.status === 0 ? (JSON.parse(result.stdout) as Timing[]) : undefined;
}

function reportRetry(what: string): (attempt: number, times: Sizes) => void {
    return (attempt, times) => {
        const now = growthOfSizes(times) ?? 'now within the bounds';
        console.warn(`scaling retry ${attempt} of ${SCALING_RETRIES}: ${what}: ${now}`);
    };
}

async function patternProblems(
    [label, command, args]: (typeof RUNNERS)[number],
    patterns: ScalingPattern[],
    attacks: Attack[],
): Promise<Problem[]> {
    const slices = shardsOf(patterns, Math.min(MAX_SHARDS, availableParallelism()));
    const runs = slices.map((slice) =>
        measure(command, args, { patterns: slice, attacks, sizes: SIZES, runs: 2 }, SCALING_DEADLINE_MS),
    );
    const results = await Promise.all(runs);
    const finished = results.filter((result): result is Timing[] => result !== undefined);
    if (finished.length < results.length) {
        return [`${label} scaling run did not finish (deadline or crash)`];
    }
    const timings = finished.flat();
    const sources = new Map(patterns.map((pattern) => [pattern.where, pattern]));
    const named = new Map(attacks.map((attack) => [attack.name, attack]));
    const keyOf = (timing: Timing): string => `${timing.where} | ${timing.attack}`;
    const problems: Problem[] = [];
    for (const [key, first] of bySizes(timings, keyOf)) {
        const again = async (): Promise<Sizes | undefined> => {
            const at = key.indexOf(' | ');
            const where = key.slice(0, at);
            const attack = key.slice(at + ' | '.length);
            const pattern = sources.get(where);
            const one = { patterns: [pattern], attacks: [named.get(attack)], sizes: SIZES, runs: 2 };
            const retimed = await measure(command, args, one, RETRY_DEADLINE_MS);
            return retimed === undefined ? undefined : bySizes(retimed, keyOf).get(key);
        };
        const isSlow = (times: Sizes): boolean => growthOfSizes(times) !== undefined;
        const times = await bestOfRetries(first, isSlow, again, reportRetry(`${label} ${key}`));
        const found = growthOfSizes(times);
        if (found !== undefined) problems.push(`${label} scaling: ${key}: ${found}`);
    }
    return problems;
}

function interpreterMessages(attack: string, times: Sizes, composite: boolean, plain: number): Problem[] {
    const small = Math.max(times[SIZES[0] as number] ?? 0, NOISE_FLOOR_MS);
    const large = times[SIZES[1] as number] ?? 0;
    const problems: Problem[] = [];
    if (composite && large > plain * MAX_COMPOSITE_FACTOR) {
        problems.push(
            `interpreter scaling: ${attack}: ${Math.round(large)} ms at 1 MB, more than ` +
                `${MAX_COMPOSITE_FACTOR} times the plain text (${Math.round(plain)} ms): a long run is measured again per start`,
        );
    }
    if (large > small * MAX_RATIO || large > MAX_INTERPRETER_MS_AT_LARGE) {
        problems.push(
            `interpreter scaling: ${attack}: ${Math.round(small)} ms at 100 KB, ${Math.round(large)} ms at 1 MB`,
        );
    }
    return problems;
}

/** Scaling through `detectSyncHits` and `detectFullHits` of the TypeScript package: the restart loops of every rule kind. */
async function interpreterProblems(attacks: Attack[]): Promise<Problem[]> {
    const script = [join(ROOT, 'tools/lint/scaling-interpreter.ts')];
    const slices = shardsOf(attacks, Math.min(MAX_SHARDS, availableParallelism()));
    const runs = slices.map((slice) =>
        measure('bun', script, { attacks: slice, sizes: SIZES }, SCALING_DEADLINE_MS),
    );
    const results = await Promise.all(runs);
    const finished = results.filter((result): result is Timing[] => result !== undefined);
    if (finished.length < results.length) {
        return ['interpreter scaling run did not finish (deadline or crash)'];
    }
    // Every slice measures the plain text too; the first slice's measurement is the baseline.
    const timings = finished.flatMap((slice, at) =>
        slice.filter((timing) => at === 0 || timing.attack !== PLAIN_ATTACK),
    );
    const composites = new Set(
        attacks.filter((attack) => attack.head !== undefined).map((attack) => attack.name),
    );
    const byAttack = bySizes(timings, (timing) => timing.attack);
    const plain = Math.max(byAttack.get(PLAIN_ATTACK)?.[SIZES[1] as number] ?? 0, COMPOSITE_FLOOR_MS);
    const named = new Map(attacks.map((attack) => [attack.name, attack]));
    const problems: Problem[] = [];
    for (const [attack, first] of byAttack) {
        const composite = composites.has(attack);
        const again = async (): Promise<Sizes | undefined> => {
            const one = named.get(attack);
            const payload = { attacks: one === undefined ? [] : [one], sizes: SIZES };
            const retimed = await measure('bun', script, payload, RETRY_DEADLINE_MS);
            if (retimed === undefined) return undefined;
            return bySizes(retimed, (timing) => timing.attack).get(attack);
        };
        const isSlow = (times: Sizes): boolean =>
            interpreterMessages(attack, times, composite, plain).length > 0;
        const times = await bestOfRetries(first, isSlow, again, reportRetry(`interpreter ${attack}`));
        problems.push(...interpreterMessages(attack, times, composite, plain));
    }
    return problems;
}

/** The three scaling runs, started together; the problems come in the order JavaScript, Python, interpreter. */
export async function scalingProblems(
    patterns: ScalingPattern[],
    attacks: Attack[],
    interpreterAttacks: Attack[] | undefined,
): Promise<Problem[]> {
    const [js, python] = RUNNERS;
    const runs = [
        patternProblems(js as (typeof RUNNERS)[number], patterns, attacks),
        patternProblems(python as (typeof RUNNERS)[number], patterns, attacks),
        interpreterAttacks === undefined ? Promise.resolve([]) : interpreterProblems(interpreterAttacks),
    ];
    return (await Promise.all(runs)).flat();
}
