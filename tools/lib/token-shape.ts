/**
 * token-shape — the conditions under which a `token` rule (SPEC 4.11) equals the backtracking expression it
 * replaces. A variable run (`min < max`, or with `tails`) is taken as the maximal run, which is what the
 * expression does only when no shorter run could let the rest match: what follows the run must not start with a
 * unit of the run's class, and a run that ends the shape needs `notAfter` to cover its class (a shorter run would
 * be followed by a unit of the class, which `notAfter` refuses). A fixed run (`min == max`) takes exactly that many
 * units and has no alternative. Also: a shape starts with a literal, alternatives of a part are not prefixes of
 * each other, tails are made of units of the run class and are not suffixes of each other.
 */
import type { SpecDir } from './spec-patterns.ts';

type Part = Record<string, unknown>;
const MAX_UNIT = 0xffff;

/** The units of a non-negated class `[...]` of the grammar (ranges, escaped punctuation). */
export function classUnits(source: string): Set<number> | undefined {
    if (!source.startsWith('[') || !source.endsWith(']') || source[1] === '^') return undefined;
    const units = new Set<number>();
    const body = source.slice(1, -1);
    const items: number[] = [];
    const isRange: boolean[] = [];
    for (let i = 0; i < body.length; i++) {
        const escaped = body[i] === '\\';
        if (escaped) i += 1;
        items.push((body[i] as string).charCodeAt(0));
        isRange.push(!escaped && body[i] === '-' && items.length > 1 && i < body.length - 1);
    }
    for (let i = 0; i < items.length; i++) {
        if (isRange[i] === true && i + 1 < items.length) {
            for (let unit = items[i - 1] as number; unit <= (items[i + 1] as number); unit++) units.add(unit);
            i += 1;
        } else units.add(items[i] as number);
    }
    return units.size > 0 && Math.max(...units) <= MAX_UNIT ? units : undefined;
}

function intersects(a: Set<number>, b: Set<number>): boolean {
    return [...a].some((unit) => b.has(unit));
}

function isSubset(a: Set<number>, b: Set<number>): boolean {
    return [...a].every((unit) => b.has(unit));
}

const isVariableRun = (part: Part): boolean =>
    'runClass' in part && (part.min !== part.max || part.tails !== undefined);
const isPrefixOfAnother = (items: string[]): boolean =>
    items.some((a, i) => items.some((b, j) => i !== j && b.startsWith(a)));
const isSuffixOfAnother = (items: string[]): boolean =>
    items.some((a, i) => items.some((b, j) => i !== j && b.endsWith(a)));

/** What may start right after `index`: the first units of a literal / alternatives / the classes of runs. */
function followerProblems(
    rule: Record<string, unknown>,
    parts: Part[],
    index: number,
    runClass: Set<number>,
    where: string,
): string[] {
    const guard = typeof rule.notAfter === 'string' ? classUnits(rule.notAfter) : undefined;
    const skippableClasses: Set<number>[] = [];
    for (let next = index + 1; next < parts.length; next++) {
        const part = parts[next] as Part;
        const startsWith = startUnits(part);
        if (startsWith === undefined) return [`${where}: cannot read the part after a variable run`];
        if (intersects(runClass, startsWith))
            return [`${where}: the part after a variable run starts with a unit of its class`];
        const isOptional = 'opt' in part || (typeof part.min === 'number' && part.min === 0);
        if (!isOptional) return [];
        skippableClasses.push(startsWith);
    }
    if (guard === undefined) return [`${where}: a variable run ends the shape without notAfter`];
    const covered = [runClass, ...skippableClasses].every((units) => isSubset(units, guard));
    return covered ? [] : [`${where}: notAfter does not cover the variable run and what may follow it`];
}

function startUnits(part: Part): Set<number> | undefined {
    if (typeof part.lit === 'string') return new Set([part.lit.charCodeAt(0)]);
    if (Array.isArray(part.alt)) return new Set((part.alt as string[]).map((item) => item.charCodeAt(0)));
    if (typeof part.runClass === 'string') return classUnits(part.runClass);
    if (Array.isArray(part.opt)) return startUnits((part.opt as Part[])[0] as Part);
    return undefined;
}

function partProblems(rule: Record<string, unknown>, parts: Part[], where: string): string[] {
    const problems: string[] = [];
    parts.forEach((part, index) => {
        const here = `${where}.parts[${index}]`;
        if (Array.isArray(part.alt) && isPrefixOfAnother(part.alt as string[]))
            problems.push(`${here}: an alternative is a prefix of another`);
        if (typeof part.runClass !== 'string') return;
        const units = classUnits(part.runClass);
        if (units === undefined)
            return void problems.push(`${here}: class is not an explicit non-negated class`);
        if (typeof part.min === 'number' && typeof part.max === 'number' && part.min > part.max)
            problems.push(`${here}: min above max`);
        if (Array.isArray(part.tails)) {
            const tails = part.tails as string[];
            if (!tails.every((tail) => [...tail].every((char) => units.has(char.charCodeAt(0)))))
                problems.push(`${here}: a tail has a unit outside the class`);
            if (isSuffixOfAnother(tails)) problems.push(`${here}: a tail is a suffix of another`);
        }
        if (isVariableRun(part)) problems.push(...followerProblems(rule, parts, index, units, here));
    });
    return problems;
}

export function tokenShapeProblems(spec: SpecDir): string[] {
    return spec.rules.full.flatMap((rule, index) => {
        if (rule.kind !== 'token') return [];
        const where = `full[${index}] ${String(rule.id)}`;
        const parts = rule.parts as Part[];
        const first = parts[0] as Part;
        const startsWithLiteral = typeof first.lit === 'string' || Array.isArray(first.alt);
        const problems = startsWithLiteral ? [] : [`${where}: a shape starts with a literal`];
        const nested = parts.flatMap((part, at) =>
            Array.isArray(part.opt)
                ? partProblems(rule, part.opt as Part[], `${where}.parts[${at}].opt`)
                : [],
        );
        return [...problems, ...partProblems(rule, parts, where), ...nested];
    });
}
