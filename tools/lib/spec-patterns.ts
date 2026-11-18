/**
 * spec-patterns — reads a spec directory and expands its patterns the way SPEC.md section 2
 * defines it. An independent implementation on purpose: the linter must not trust the
 * package's own expander.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

type WordMacro = { join: string; words?: string[][]; fromKeys?: string };
type Macro = string | WordMacro;
export type SpecDir = {
    rules: {
        macros: Record<string, Macro>;
        patterns: Record<string, string>;
        pipeline: Array<Record<string, unknown>>;
    };
    keys: Record<string, unknown>;
    algorithms: Record<string, unknown>;
};
export type NamedPattern = { where: string; role: 'pattern' | 'class'; source: string };

export function readSpecDir(dir: string): SpecDir {
    const read = (name: string): never => JSON.parse(readFileSync(join(dir, name), 'utf8')) as never;
    return { rules: read('rules.json'), keys: read('keys.json'), algorithms: read('algorithms.json') };
}

function caseInsensitive(part: string): string {
    return [...part].map((char) => (/^[a-z]$/.test(char) ? `[${char}${char.toUpperCase()}]` : char)).join('');
}

function expandWords(macro: WordMacro, keys: Record<string, unknown>): string {
    const sequences =
        macro.fromKeys === undefined ? (macro.words ?? []) : (keys[macro.fromKeys] as string[][]);
    const alternatives = sequences.map((parts) => parts.map(caseInsensitive).join(macro.join));
    return `(?:${alternatives.join('|')})`;
}

export function expand(template: string, spec: SpecDir, depth = 0): string {
    if (depth > 8) throw new Error('macros nest too deep');
    const out = template.replace(/\{\{([A-Z_]+)\}\}/g, (_, name: string) => {
        const macro = spec.rules.macros[name];
        if (macro === undefined) throw new Error(`unknown macro ${name}`);
        return typeof macro === 'string' ? macro : expandWords(macro, spec.keys);
    });
    return out === template ? out : expand(out, spec, depth + 1);
}

/** Fields of a pipeline entry that hold a regular expression, and whether it is one character class. */
const PATTERN_FIELDS: Record<string, 'pattern' | 'class'> = {
    pattern: 'pattern',
    notBefore: 'class',
    notAfter: 'class',
    requireClass: 'class',
    header: 'pattern',
    footer: 'pattern',
    bodyChar: 'class',
    prefix: 'pattern',
    plainChar: 'class',
    escapeStop: 'class',
    bearer: 'pattern',
    scheme: 'pattern',
    valueClass: 'class',
    lowerClass: 'class',
    upperClass: 'class',
    wordClass: 'class',
    identChar: 'class',
    label: 'pattern',
    queryKey: 'pattern',
    valueEnd: 'class',
    nestedEnd: 'class',
};

/** Every expanded pattern of the spec with a label saying where it came from. */
export function collectPatterns(spec: SpecDir): NamedPattern[] {
    const found: NamedPattern[] = [];
    spec.rules.pipeline.forEach((rule, index) => {
        for (const [field, role] of Object.entries(PATTERN_FIELDS)) {
            const value = rule[field];
            if (typeof value !== 'string') continue;
            found.push({
                where: `pipeline[${index}] ${String(rule.id)} (${String(rule.kind)}).${field}`,
                role,
                source: expand(value, spec),
            });
        }
    });
    found.push({
        where: 'patterns.placeholder',
        role: 'pattern',
        source: expand(spec.rules.patterns.placeholder as string, spec),
    });
    const algorithms = spec.algorithms as {
        evidence: { classes: string[] };
        trivial: { wrapperInner: string };
        docPlaceholder: { separator: string };
    };
    for (const source of algorithms.evidence.classes)
        found.push({ where: 'evidence.classes', role: 'class', source });
    found.push({ where: 'trivial.wrapperInner', role: 'class', source: algorithms.trivial.wrapperInner });
    found.push({
        where: 'docPlaceholder.separator',
        role: 'class',
        source: algorithms.docPlaceholder.separator,
    });
    return found;
}
