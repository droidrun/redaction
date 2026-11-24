/**
 * recheck-gate — the ReDoS gate on one pattern. `recheck` (static analysis) must say "safe". A verdict that is not
 * "safe" is never erased by a later run (recheck's fuzz checker measures time, so a loaded machine can make a safe
 * pattern look vulnerable, and a seed that says "safe" proves nothing). Instead the attack string that recheck
 * produced is built at 100 KB and 1 MB and run through the scaling harness in JavaScript and Python:
 *
 *   - the growth is confirmed (ratio or absolute bound exceeded, or the run does not finish): the pattern FAILS and
 *     the problem carries the attack;
 *   - the harness does not confirm it: the pattern passes with a WARNING that carries the attack string, so the
 *     doubt is visible in the CI log and can be looked at;
 *   - recheck cannot decide (status "unknown") or gives no attack string: the pattern FAILS.
 */
import { check } from 'recheck';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Attack } from './attacks.ts';
import { CACHE_FORMAT, hashParts, type GateCache } from './recheck-cache.ts';

const ROOT = resolve(import.meta.dir, '..', '..');
export const SIZES = [100_000, 1_000_000];
export const MAX_RATIO = 30;
export const NOISE_FLOOR_MS = 10;
export const MAX_MS_AT_LARGE = 3000;
const CONFIRM_DEADLINE_MS = 20_000;
const RECHECK_TIMEOUT_MS = 60_000;
const RECHECK_FLAGS = '';

type Pump = { prefix: string; pump: string; bias: number };
export type RecheckAttack = { pumps: Pump[]; suffix: string; base: number; string: string };
export type Timing = { where: string; attack: string; size: number; ms: number };

/** The attack string at about `size` units: every pump repeated as often as the size allows (bias kept). */
export function attackAtSize(attack: RecheckAttack, size: number): string {
    const fixed = attack.suffix.length + attack.pumps.reduce((sum, pump) => sum + pump.prefix.length, 0);
    const unit = Math.max(
        1,
        attack.pumps.reduce((sum, pump) => sum + pump.pump.length, 0),
    );
    const repeats = Math.max(1, Math.floor((size - fixed) / unit));
    const body = attack.pumps.map((pump) => pump.prefix + pump.pump.repeat(Math.max(0, repeats + pump.bias)));
    return body.join('') + attack.suffix;
}

export const RUNNERS: Array<[label: string, command: string, args: string[]]> = [
    ['JavaScript', 'bun', [join(ROOT, 'tools/lint/scaling.ts')]],
    ['Python', 'python3', ['-I', join(ROOT, 'tools/lint/scaling.py')]],
];

/** Runs the scaling harness; `undefined` when it did not finish in time (a super-linear sign of its own). */
export function runScaling(
    command: string,
    args: string[],
    payload: unknown,
    deadlineMs: number,
): Timing[] | undefined {
    const result = spawnSync(command, args, {
        input: JSON.stringify(payload),
        encoding: 'utf8',
        timeout: deadlineMs,
        maxBuffer: 256 * 1024 * 1024,
    });
    return result.status === 0 ? (JSON.parse(result.stdout) as Timing[]) : undefined;
}

/** The growth of one pattern over one attack: a description when it is super-linear, else undefined. */
export function growth(timings: Timing[]): string | undefined {
    return growthOfSizes(Object.fromEntries(timings.map((timing) => [timing.size, timing.ms])));
}

/** The same decision over the times by size. */
export function growthOfSizes(times: Record<number, number>): string | undefined {
    const small = Math.max(times[SIZES[0] as number] ?? 0, NOISE_FLOOR_MS);
    const large = times[SIZES[1] as number] ?? 0;
    if (large <= small * MAX_RATIO && large <= MAX_MS_AT_LARGE) return undefined;
    return `${Math.round(small)} ms at 100 KB, ${Math.round(large)} ms at 1 MB`;
}

/** Confirms a recheck attack with the scaling harness in every language; the description, or undefined. */
export function confirmAttack(where: string, source: string, attack: RecheckAttack): string | undefined {
    const texts = Object.fromEntries(SIZES.map((size) => [String(size), attackAtSize(attack, size)]));
    const named: Attack = { name: 'recheck attack', unit: attack.pumps[0]?.pump ?? 'a', texts };
    const payload = { patterns: [{ where, source }], attacks: [named], sizes: SIZES, runs: 1 };
    for (const [label, command, args] of RUNNERS) {
        const timings = runScaling(command, args, payload, CONFIRM_DEADLINE_MS);
        if (timings === undefined)
            return `${label}: the run did not finish in ${CONFIRM_DEADLINE_MS / 1000} s`;
        const found = growth(timings);
        if (found !== undefined) return `${label}: ${found}`;
    }
    return undefined;
}

function show(attack: RecheckAttack): string {
    const text = JSON.stringify(
        attack.string.length > 120 ? `${attack.string.slice(0, 120)}…` : attack.string,
    );
    return `attack ${text}, pumps ${JSON.stringify(attack.pumps.map((pump) => pump.pump))}`;
}

export type Gate = { problem?: string; warning?: string };

type Deps = {
    check: (
        source: string,
    ) => Promise<{ status: string; attack?: unknown; complexity?: { summary?: string } }>;
    confirm: (where: string, source: string, attack: RecheckAttack) => string | undefined;
};

const REAL: Deps = {
    check: (source) => check(source, RECHECK_FLAGS, { timeout: RECHECK_TIMEOUT_MS } as never) as ReturnType<Deps['check']>,
    confirm: confirmAttack,
};

/** The verdict on one pattern. `deps` is for the tests of the decision logic. */
export async function recheckGate(where: string, source: string, deps: Deps = REAL): Promise<Gate> {
    const result = await deps.check(source);
    if (result.status === 'safe') return {};
    const attack = (result as { attack?: RecheckAttack }).attack;
    if (result.status !== 'vulnerable' || attack === undefined) {
        return { problem: `${where}: recheck says ${result.status} (no attack string to confirm)` };
    }
    const confirmed = deps.confirm(where, source, attack);
    if (confirmed !== undefined) {
        return {
            problem: `${where}: recheck says vulnerable and the scaling run confirms it (${confirmed}); ${show(attack)}`,
        };
    }
    return {
        warning:
            `${where}: recheck says vulnerable (${result.complexity?.summary ?? 'complexity unknown'}) but the ` +
            `scaling run over its attack string stays linear in JavaScript and Python; ${show(attack)}`,
    };
}

function recheckVersion(): string {
    const path = join(ROOT, 'tools', 'node_modules', 'recheck', 'package.json');
    return (JSON.parse(readFileSync(path, 'utf8')) as { version: string }).version;
}

/** What a stored decision depends on: the package version, every gate setting and the pattern. */
export function gateKey(source: string): string {
    const settings = [RECHECK_TIMEOUT_MS, CONFIRM_DEADLINE_MS, MAX_RATIO, NOISE_FLOOR_MS, MAX_MS_AT_LARGE];
    return hashParts([
        `format ${CACHE_FORMAT}`,
        `recheck ${recheckVersion()}`,
        `settings ${[...settings, ...SIZES].join(',')}`,
        `flags ${RECHECK_FLAGS}`,
        source,
    ]);
}

/** A decision is stored without its label (`where: `), so moving a rule in its list does not miss. */
function relabel(gate: Gate, from: string, to: string): Gate {
    const swap = (text: string): string => `${to}: ${text.slice(`${from}: `.length)}`;
    return {
        ...(gate.problem === undefined ? {} : { problem: swap(gate.problem) }),
        ...(gate.warning === undefined ? {} : { warning: swap(gate.warning) }),
    };
}

const STORED_LABEL = '';

/** `recheckGate` behind the cache; `cache` undefined means a full analysis. */
export async function cachedRecheckGate(
    where: string,
    source: string,
    cache: GateCache | undefined,
    deps: Deps = REAL,
): Promise<Gate> {
    if (cache === undefined) return recheckGate(where, source, deps);
    const key = gateKey(source);
    const stored = cache.get(key);
    if (stored !== undefined) return relabel(stored, STORED_LABEL, where);
    const gate = await recheckGate(where, source, deps);
    cache.set(key, relabel(gate, where, STORED_LABEL));
    return gate;
}
