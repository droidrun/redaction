/**
 * grammar — the portable regex grammar of SPEC.md section 2, as a checker. Returns the
 * violations of one expanded pattern (empty when it is portable).
 *
 * Banned: shorthand classes (`\s \S \w \W \d \D`), the dot, anchors (`^` outside a class start,
 * `$`), lookaround, back-references, named groups, inline flags, escapes other than `\b` and
 * escaped punctuation, `[` inside a class, repeat bounds above 1000, possessive quantifiers,
 * unbounded lazy quantifiers and lazy bounds above 64, and a repeated group that holds a
 * repeating quantifier (nested quantifiers).
 */
const MAX_BOUND = 1000;
const MAX_LAZY_BOUND = 64;
const ESCAPABLE = new Set([...'\\[](){}.*+?|^$-/"\':<>=!,;#&%@~`_ ']);

type Group = { repeats: boolean };
type Quantifier = { repeats: boolean; max: number | null; end: number };

function describeEscape(char: string): string {
    if ('sSwWdD'.includes(char)) return `shorthand class \\${char}`;
    if (/[0-9]/.test(char)) return `back-reference \\${char}`;
    if (char === 'k') return 'named back-reference \\k';
    return `escape \\${char} (only \\b and escaped punctuation are portable)`;
}

function checkEscape(char: string | undefined, inClass: boolean, out: string[]): void {
    if (char === undefined) {
        out.push('pattern ends with a lone backslash');
        return;
    }
    if (char === 'b' && !inClass) return;
    if (ESCAPABLE.has(char)) return;
    out.push(describeEscape(char));
}

/** The quantifier that starts at `at` (`*`, `+`, `?` or a `{n,m}` bound): its largest count and end. */
function readQuantifier(source: string, at: number, out: string[]): Quantifier {
    const char = source[at];
    if (char === '*' || char === '+') return { repeats: true, max: null, end: at };
    if (char === '?') return { repeats: false, max: 1, end: at };
    const close = source.indexOf('}', at);
    const match = /^(\d+)(?:(,)(\d*))?$/.exec(close === -1 ? '' : source.slice(at + 1, close));
    if (!match) {
        out.push('"{" that is not a repeat bound');
        return { repeats: false, max: 1, end: at };
    }
    const min = Number(match[1]);
    const max = match[2] === undefined ? min : match[3] === '' ? null : Number(match[3]);
    for (const bound of [min, max]) {
        if (bound !== null && bound > MAX_BOUND) out.push(`repeat bound ${bound} above ${MAX_BOUND}`);
    }
    return { repeats: max === null || max > 1, max, end: close };
}

function checkGroupOpen(source: string, at: number, out: string[]): void {
    if (source[at + 1] === '?' && source[at + 2] !== ':') {
        out.push(`group syntax (?${source[at + 2] ?? ''} (lookaround, named group or inline flag)`);
    }
}

export function grammarViolations(source: string): string[] {
    const out: string[] = [];
    const groups: Group[] = [{ repeats: false }];
    let inClass = false;
    let classStart = -1;
    let closed: Group | null = null;
    let afterQuantifier = false;
    let lastQuantifier: Quantifier | undefined;
    for (let i = 0; i < source.length; i++) {
        const char = source[i] as string;
        const justClosed = closed;
        closed = null;
        if (char === '\\') {
            checkEscape(source[i + 1], inClass, out);
            i += 1;
            afterQuantifier = false;
            continue;
        }
        if (inClass) {
            if (char === '[') out.push('"[" inside a class (escape it)');
            if (char === '^' && i !== classStart + 1) out.push('"^" inside a class is not at its start');
            if (char === ']') inClass = false;
            continue;
        }
        if (char === '[') {
            inClass = true;
            classStart = i;
            afterQuantifier = false;
            continue;
        }
        if (char === '(') {
            checkGroupOpen(source, i, out);
            groups.push({ repeats: false });
            afterQuantifier = false;
            continue;
        }
        if (char === ')') {
            const group = groups.length > 1 ? (groups.pop() as Group) : { repeats: false };
            (groups[groups.length - 1] as Group).repeats ||= group.repeats;
            closed = group;
            afterQuantifier = false;
            continue;
        }
        if (char === '*' || char === '+' || char === '?' || char === '{') {
            if (afterQuantifier && char === '?') {
                if (lastQuantifier === undefined) out.push('stacked quantifiers');
                else checkLazy(lastQuantifier.max, out);
                afterQuantifier = false;
                continue;
            }
            if (afterQuantifier) out.push(char === '+' ? 'possessive quantifier' : 'stacked quantifiers');
            const quantifier = readQuantifier(source, i, out);
            i = quantifier.end;
            if (quantifier.repeats) {
                if (justClosed?.repeats)
                    out.push('nested quantifier: a repeated group holds a repeating quantifier');
                (groups[groups.length - 1] as Group).repeats = true;
            }
            lastQuantifier = quantifier;
            afterQuantifier = true;
            continue;
        }
        if (char === '.') out.push('the dot (write the class)');
        if (char === '^' || char === '$') out.push(`anchor ${char}`);
        afterQuantifier = false;
    }
    if (inClass) out.push('unterminated class');
    if (groups.length !== 1) out.push('unbalanced parentheses');
    return out;
}

function checkLazy(max: number | null, out: string[]): void {
    if (max === null || max > MAX_LAZY_BOUND)
        out.push(`lazy quantifier with a bound above ${MAX_LAZY_BOUND}`);
}

const RULE_ID = /^[a-z0-9-]+$/;

export function ruleIdViolation(id: string): string | undefined {
    return RULE_ID.test(id) ? undefined : `rule id "${id}" does not match ^[a-z0-9-]+$`;
}
