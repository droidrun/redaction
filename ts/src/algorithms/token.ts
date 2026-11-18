/**
 * token — the key formats of the full tier (SPEC 4.11): a shape of literals and runs of units of a class,
 * an optional letter guard in front and a class that must not follow. Same matches as the lookaround
 * expressions it replaces (`(?<!\p{L})prefix_[A-Za-z0-9]{36}(?![A-Za-z0-9_])`) but deterministic: a
 * variable run is the maximal run, so there is nothing to backtrack into, and every start does bounded work.
 * The linter checks the conditions under which that equals the backtracking expression.
 */
import { charTest, type CharTest, type Range } from '../portable.js';
import type { Rule } from '../spec.js';
import { isBase64Json } from './base64-json.js';
import { passesLetterGuard } from './letters.js';
import type { Scanner } from './regex-rule.js';
import { cachedRunEnd, nextStartOf, type RunEnd } from './scan-support.js';

type Part =
    | { lit: string }
    | { alt: string[] }
    | { runClass: string; min: number; max: number; tails?: string[] }
    | { opt: Part[] };
type TokenRule = Rule & {
    letterGuard?: boolean;
    parts: Part[];
    notAfter?: string;
    check?: string;
    checkFrom?: number;
};

type Context = { text: string; runEnd: (classSource: string) => RunEnd };
type Continue = (position: number) => number;
type Step = (context: Context, position: number, next: Continue) => number;

const FAIL = -1;
const CHECKS: Record<string, (value: string) => boolean> = { 'base64-json': isBase64Json };

function literalStep(literal: string): Step {
    return ({ text }, position, next) =>
        text.startsWith(literal, position) ? next(position + literal.length) : FAIL;
}

function alternativeStep(literals: string[]): Step {
    return ({ text }, position, next) => {
        const literal = literals.find((item) => text.startsWith(item, position));
        return literal === undefined ? FAIL : next(position + literal.length);
    };
}

/** Exactly `count` units of the class. */
function fixedRunStep(inClass: CharTest, count: number): Step {
    return ({ text }, position, next) => {
        if (position + count > text.length) return FAIL;
        for (let at = position; at < position + count; at++) {
            if (!inClass(text[at] as string)) return FAIL;
        }
        return next(position + count);
    };
}

/** The maximal run; `tails` (first one the run ends with) are part of the run but not counted. */
function maximalRunStep(part: { runClass: string; min: number; max: number; tails?: string[] }): Step {
    return (context, position, next) => {
        const end = context.runEnd(part.runClass)(position);
        const length = end - position;
        const tail = part.tails?.find(
            (item) => length >= item.length && context.text.startsWith(item, end - item.length),
        );
        if (part.tails !== undefined && tail === undefined) return FAIL;
        const counted = length - (tail?.length ?? 0);
        return counted < part.min || counted > part.max ? FAIL : next(end);
    };
}

function sequence(steps: Step[], index: number, context: Context, position: number, next: Continue): number {
    const step = steps[index];
    if (step === undefined) return next(position);
    return step(context, position, (after) => sequence(steps, index + 1, context, after, next));
}

function optionalStep(inner: Step[]): Step {
    return (context, position, next) => {
        const withGroup = sequence(inner, 0, context, position, next);
        return withGroup !== FAIL ? withGroup : next(position);
    };
}

function compilePart(part: Part): Step {
    if ('lit' in part) return literalStep(part.lit);
    if ('alt' in part) return alternativeStep(part.alt);
    if ('opt' in part) return optionalStep(part.opt.map(compilePart));
    const isFixed = part.min === part.max && part.tails === undefined;
    return isFixed ? fixedRunStep(charTest(part.runClass), part.min) : maximalRunStep(part);
}

function firstLiterals(first: Part | undefined): string[] {
    if (first !== undefined && 'lit' in first) return [first.lit];
    if (first !== undefined && 'alt' in first) return first.alt;
    throw new Error('a token shape starts with a literal');
}

/** Every distinct class of a variable run in the shape (the scan keeps one run memory per class). */
function runClasses(parts: Part[]): string[] {
    return parts.flatMap((part) => {
        if ('opt' in part) return runClasses(part.opt);
        return 'runClass' in part ? [part.runClass] : [];
    });
}

export function prepareToken(rule: TokenRule): Scanner {
    const steps = rule.parts.map(compilePart);
    const starts = firstLiterals(rule.parts[0]);
    const classes = [...new Set(runClasses(rule.parts))];
    const blocksAfter = rule.notAfter === undefined ? () => false : charTest(rule.notAfter);
    const check = rule.check === undefined ? undefined : (CHECKS[rule.check] as (value: string) => boolean);
    return (text) => {
        const ends = new Map(classes.map((source) => [source, cachedRunEnd(text, charTest(source))]));
        const context: Context = { text, runEnd: (source) => ends.get(source) as RunEnd };
        const endGuard: Continue = (position) =>
            position < text.length && blocksAfter(text[position] as string) ? FAIL : position;
        const nextStart = nextStartOf(text, starts);
        const ranges: Range[] = [];
        let from = 0;
        for (let start = nextStart(from); start !== -1; start = nextStart(from)) {
            from = start + 1;
            if (rule.letterGuard === true && !passesLetterGuard(text, start)) continue;
            const end = sequence(steps, 0, context, start, endGuard);
            if (end === FAIL) continue;
            from = end;
            const checked = check === undefined || check(text.slice(start + (rule.checkFrom ?? 0), end));
            if (checked) ranges.push([start, end]);
        }
        return ranges;
    };
}
