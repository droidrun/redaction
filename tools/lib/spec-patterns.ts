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

/** String fields of a pipeline entry that hold literal text, not a regular expression. */
const LITERAL_FIELDS = new Set(['id', 'kind', 'lead', 'separator', 'footerMarker', 'requireLiteral']);
/** Fields that hold a pattern (the other regex-bearing fields hold one character class). */
const PATTERN_FIELDS = new Set([
    'pattern',
    'header',
    'footer',
    'prefix',
    'bearer',
    'scheme',
    'label',
    'queryKey',
]);
const CLASS_FIELD = /(?:Class|Char|Stop|End)$|^notBefore$|^notAfter$/;

export type FieldRole = 'literal' | 'pattern' | 'class' | 'unknown';

/** What a string field of a pipeline entry holds, decided by its name. */
export function fieldRole(name: string): FieldRole {
    if (LITERAL_FIELDS.has(name)) return 'literal';
    if (PATTERN_FIELDS.has(name)) return 'pattern';
    return CLASS_FIELD.test(name) ? 'class' : 'unknown';
}

/** String fields no rule of the linter knows: they would escape every check, so they are a problem. */
export function unclassifiedFields(spec: SpecDir): string[] {
    return spec.rules.pipeline.flatMap((rule, index) => {
        return Object.entries(rule)
            .filter(([name, value]) => typeof value === 'string' && fieldRole(name) === 'unknown')
            .map(
                ([name]) =>
                    `pipeline[${index}] ${String(rule.id)}.${name}: ` +
                    'a string field the linter cannot classify',
            );
    });
}

/** Every expanded pattern of the spec with a label saying where it came from. */
export function collectPatterns(spec: SpecDir): NamedPattern[] {
    const found: NamedPattern[] = [];
    spec.rules.pipeline.forEach((rule, index) => {
        for (const [field, value] of Object.entries(rule)) {
            const role = fieldRole(field);
            if (typeof value !== 'string' || role === 'literal' || role === 'unknown') continue;
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
