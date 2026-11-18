/**
 * token — the key formats of the full tier (SPEC 4.11): a shape of literals and runs of units of a class,
 * an optional letter guard in front and a class that must not follow. Same matches as the lookaround
 * expressions it replaces (`(?<!\p{L})prefix_[A-Za-z0-9]{36}(?![A-Za-z0-9_])`) but deterministic: a
 * variable run is the maximal run, so there is nothing to backtrack into. The run a part measured at one start
 * is remembered per PART for the next starts (SPEC 4.11), so a scan stays linear in the text; a memory per
 * class would be overwritten by the other parts of the same class and measure the long run again at every start.
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

/** `memo[i]` is the run memory of the variable-run part number `i`, made when the part first runs in a scan. */
type Context = { text: string; memo: Array<RunEnd | undefined> };
type Continue = (position: number) => number;
type Step = (context: Context, position: number, next: Continue) => number;

const FAIL = -1;
const CHECKS: Record<string, (value: string) => boolean> = { 'base64-json': isBase64Json };

/** Numbers the variable-run parts of one rule, in the order they are compiled. */
type Counter = { next: number };

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
function maximalRunStep(
    part: { runClass: string; min: number; max: number; tails?: string[] },
    id: number,
): Step {
    const inClass = charTest(part.runClass);
    return (context, position, next) => {
        const runEnd = (context.memo[id] ??= cachedRunEnd(context.text, inClass));
        const end = runEnd(position);
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

function compilePart(part: Part, counter: Counter): Step {
    if ('lit' in part) return literalStep(part.lit);
    if ('alt' in part) return alternativeStep(part.alt);
    if ('opt' in part) return optionalStep(part.opt.map((inner) => compilePart(inner, counter)));
    const isFixed = part.min === part.max && part.tails === undefined;
    if (isFixed) return fixedRunStep(charTest(part.runClass), part.min);
    counter.next += 1;
    return maximalRunStep(part, counter.next - 1);
}

function firstLiterals(first: Part | undefined): string[] {
    if (first !== undefined && 'lit' in first) return [first.lit];
    if (first !== undefined && 'alt' in first) return first.alt;
    throw new Error('a token shape starts with a literal');
}

export function prepareToken(rule: TokenRule): Scanner {
    const counter: Counter = { next: 0 };
    const steps = rule.parts.map((part) => compilePart(part, counter));
    const starts = firstLiterals(rule.parts[0]);
    const blocksAfter = rule.notAfter === undefined ? () => false : charTest(rule.notAfter);
    const check = rule.check === undefined ? undefined : CHECKS[rule.check];
    if (rule.check !== undefined && check === undefined) throw new Error('unknown check in the spec');
    return (text) => {
        const context: Context = { text, memo: [] };
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
