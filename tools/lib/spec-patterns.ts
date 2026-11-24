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
        strict: Array<Record<string, unknown>>;
        pii: Array<Record<string, unknown>>;
        full: Array<Record<string, unknown>>;
    };
    keys: Record<string, unknown>;
    algorithms: Record<string, unknown>;
};
/** `rule` is the id and kind of the rule a pattern belongs to; the patterns of the algorithm data have none. */
export type NamedPattern = {
    where: string;
    role: 'pattern' | 'class';
    source: string;
    rule?: { id?: string; kind?: string };
};

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

/** String fields of a rule that hold literal text, not a regular expression. */
const LITERAL_FIELDS = new Set([
    'id',
    'kind',
    'lead',
    'leads',
    'separator',
    'footerMarker',
    'requireLiteral',
    'lit',
    'alt',
    'tails',
    'magic',
    'ignoreEquals',
    'userIgnoreContains',
    'passwordIgnoreContains',
    'passwordIgnoreEquals',
    'stripLiteral',
    'newline',
    'dash',
    'check',
    'plainWords',
    'queryOnlyKeys',
    'ignoreSuffixes',
    'ignoreAfterWords',
    'statusWords',
    'schemeKeys',
    'schemeWords',
]);
/** Fields that hold a pattern (the other regex-bearing fields hold one character class). */
const PATTERN_FIELDS = new Set([
    'pattern',
    'header',
    'footer',
    'prefix',
    'bearer',
    'bearerAlso',
    'scheme',
    'label',
    'queryKey',
    'variablePatterns',
]);
const CLASS_FIELD = /(?:Class|Char|Stop|End)$|^notBefore$|^notAfter$/;

export type FieldRole = 'literal' | 'pattern' | 'class' | 'unknown';

/** What a string field of a rule holds, decided by its name. */
export function fieldRole(name: string): FieldRole {
    if (LITERAL_FIELDS.has(name)) return 'literal';
    if (PATTERN_FIELDS.has(name)) return 'pattern';
    return CLASS_FIELD.test(name) ? 'class' : 'unknown';
}

export type RuleList = 'pipeline' | 'strict' | 'pii' | 'full';
export const RULE_LISTS: RuleList[] = ['pipeline', 'strict', 'pii', 'full'];
type StringField = { path: string; name: string; value: string };

/** Every string of a rule (also inside nested parts and lists of strings), with the name of its field. */
function stringFields(value: unknown, path: string, name: string, out: StringField[]): void {
    if (typeof value === 'string') out.push({ path, name, value });
    else if (Array.isArray(value))
        value.forEach((item, index) => stringFields(item, `${path}[${index}]`, name, out));
    else if (value !== null && typeof value === 'object') {
        for (const [key, item] of Object.entries(value)) stringFields(item, `${path}.${key}`, key, out);
    }
}

function ruleStrings(rule: Record<string, unknown>, path: string): StringField[] {
    const out: StringField[] = [];
    for (const [key, item] of Object.entries(rule)) stringFields(item, `${path}.${key}`, key, out);
    return out;
}

/** String fields no rule of the linter knows: they would escape every check, so they are a problem. */
export function unclassifiedFields(spec: SpecDir): string[] {
    return RULE_LISTS.flatMap((list) =>
        spec.rules[list].flatMap((rule, index) =>
            ruleStrings(rule, `${list}[${index}] ${String(rule.id)}`)
                .filter((field) => fieldRole(field.name) === 'unknown')
                .map((field) => `${field.path}: a string field the linter cannot classify`),
        ),
    );
}

const stringOrUndefined = (value: unknown): string | undefined =>
    typeof value === 'string' ? value : undefined;

/** Whether a rule is named by an `--only` list of rule ids and kinds. */
export function isSelected(rule: { id?: string; kind?: string } | undefined, only: string[]): boolean {
    if (rule === undefined) return false;
    const byId = rule.id !== undefined && only.includes(rule.id);
    const byKind = rule.kind !== undefined && only.includes(rule.kind);
    return byId || byKind;
}

/** Every expanded pattern of the spec with a label saying where it came from. */
export function collectPatterns(spec: SpecDir): NamedPattern[] {
    const found: NamedPattern[] = [];
    for (const list of RULE_LISTS) {
        spec.rules[list].forEach((rule, index) => {
            for (const field of ruleStrings(
                rule,
                `${list}[${index}] ${String(rule.id)} (${String(rule.kind)})`,
            )) {
                const role = fieldRole(field.name);
                if (role === 'literal' || role === 'unknown') continue;
                found.push({
                    where: field.path,
                    role,
                    source: expand(field.value, spec),
                    rule: { id: stringOrUndefined(rule.id), kind: stringOrUndefined(rule.kind) },
                });
            }
        });
    }
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
