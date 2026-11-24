/**
 * spec.ts — the language-neutral rule spec as the generated module `spec-data.generated.ts`
 * (written by `tools/sync-spec`, which also checks it against `spec/` in CI and on release).
 * Nothing here touches the file system, the clock or a Node built-in, so every entry runs in
 * any JavaScript runtime. Refuses to start on an unsupported version or an empty rule set, and
 * expands the pattern macros. Nothing in `src/` restates a rule, word list or threshold of the
 * spec: it all comes from here.
 */
import { ALGORITHMS_DATA, KEYS_DATA, RULES_DATA } from './spec-data.generated.js';

export type WordMacro = { join: string; words?: string[][]; fromKeys?: string };
export type Macro = string | WordMacro;
export type Rule = { id: string; kind: string; [param: string]: unknown };
/** One edit of `rules.json` `strict`: the entries matching `id` and `kind` (those given) get their fields
 *  `set`, or (exactly one entry) get the rule `add`ed right after them. */
export type StrictEdit = { id?: string; kind?: string; set?: Record<string, unknown>; add?: Rule };
export type RulesSpec = {
    specVersion: number;
    macros: Record<string, Macro>;
    patterns: { placeholder: string };
    pipeline: Rule[];
    strict: StrictEdit[];
    pii: Rule[];
    full: Rule[];
};
export type KeysSpec = {
    specVersion: number;
    structuralSkipKeys: string[];
    secretWords: string[][];
    extraSequences: string[][];
    exactKeys: string[];
    joinedExtra: string[];
    suffixWords: string[];
    prefixWords: string[];
    passLastWord: string;
    countWords: string[];
};
export type AlgorithmsSpec = {
    specVersion: number;
    ruleIds: {
        keyContext: string;
        sizeLimit: string;
        depthLimit: string;
        circular: string;
        failed: string;
        error: string;
    };
    text: { minScanLength: number };
    placeholder: { open: string; close: string; numberMark: string; stripPrefixes: string[] };
    evidence: { quoteChars: string; classes: string[]; minClasses: number; entropyThreshold: number };
    trivial: { words: string[]; maskChars: string[]; wrappers: string[][]; wrapperInner: string };
    docPlaceholder: { prefixes: string[]; suffixes: string[]; separator: string };
    sync: { maxChars: number; maxDepth: number; maxNodes: number; maxKeyChars: number };
    full: { scanWindow: number; scanOverlap: number; scanCap: number };
    strict: { maxChars: number; maxDepth: number; maxNodes: number };
    letters: { unicodeVersion: string; ranges: string };
};

const SPEC_SUPPORTED_VERSION = 1;
const MACRO_REFERENCE = /\{\{([A-Z_]+)\}\}/g;
const MAX_MACRO_DEPTH = 8;

function checked<T extends { specVersion: number }>(data: unknown): T {
    const spec = data as T;
    if (spec.specVersion !== SPEC_SUPPORTED_VERSION) throw new Error('unsupported redaction spec version');
    return spec;
}

function loadSpec(): { rules: RulesSpec; keys: KeysSpec; algorithms: AlgorithmsSpec } {
    const rules = checked<RulesSpec>(RULES_DATA);
    const keys = checked<KeysSpec>(KEYS_DATA);
    const algorithms = checked<AlgorithmsSpec>(ALGORITHMS_DATA);
    const hasNoRules = rules.pipeline.length === 0 || rules.pii.length === 0 || rules.full.length === 0;
    if (!Array.isArray(rules.strict)) throw new Error('redaction spec holds no strict rules');
    if (hasNoRules || keys.secretWords.length === 0) {
        throw new Error('redaction spec holds no rules');
    }
    return { rules, keys, algorithms };
}

const LOADED = loadSpec();
export const RULES_SPEC: RulesSpec = LOADED.rules;
export const KEYS_SPEC: KeysSpec = LOADED.keys;
export const ALGORITHMS_SPEC: AlgorithmsSpec = LOADED.algorithms;

function matchesEdit(rule: Rule, edit: StrictEdit): boolean {
    const isId = edit.id === undefined || rule.id === edit.id;
    const isKind = edit.kind === undefined || rule.kind === edit.kind;
    return isId && isKind;
}

function applyEdit(rules: Rule[], edit: StrictEdit): Rule[] {
    const targets = rules.filter((rule) => matchesEdit(rule, edit));
    if (targets.length === 0) throw new Error('a strict edit of the spec matches no rule');
    if (edit.add !== undefined) {
        if (targets.length !== 1) throw new Error('a strict edit that adds a rule must match one rule');
        const at = rules.indexOf(targets[0] as Rule);
        return [...rules.slice(0, at + 1), edit.add, ...rules.slice(at + 1)];
    }
    return rules.map((rule) => (matchesEdit(rule, edit) ? { ...rule, ...edit.set } : rule));
}

/** The `strict` rule list (SPEC 4.10): the `compat` list (`pipeline`) with the `strict` edits applied. */
export function strictRules(rules: readonly Rule[]): Rule[] {
    return LOADED.rules.strict.reduce(applyEdit, [...rules]);
}

/** An ASCII letter as a two-case class (`a` -> `[aA]`); other characters as they are. */
function caseInsensitiveChar(char: string): string {
    const isLetter = /^[a-z]$/.test(char);
    return isLetter ? `[${char}${char.toUpperCase()}]` : char;
}

function expandWordMacro(macro: WordMacro): string {
    const sequences =
        macro.fromKeys === undefined
            ? (macro.words ?? [])
            : ((LOADED.keys as unknown as Record<string, string[][]>)[macro.fromKeys] ?? []);
    const alternatives = sequences.map((parts) => {
        return parts.map((part) => [...part].map(caseInsensitiveChar).join('')).join(macro.join);
    });
    return `(?:${alternatives.join('|')})`;
}

function expandMacro(name: string): string {
    const macro = LOADED.rules.macros[name];
    if (macro === undefined) throw new Error('unknown spec macro');
    return typeof macro === 'string' ? macro : expandWordMacro(macro);
}

/** The pattern with every `{{MACRO}}` replaced (macros may use other macros). */
export function expandPattern(template: string, depth = 0): string {
    if (depth > MAX_MACRO_DEPTH) throw new Error('spec macros nest too deep');
    const expanded = template.replace(MACRO_REFERENCE, (_, name: string) => expandMacro(name));
    return expanded === template ? expanded : expandPattern(expanded, depth + 1);
}
