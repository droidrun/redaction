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
export type RulesSpec = {
    specVersion: number;
    macros: Record<string, Macro>;
    patterns: { placeholder: string };
    pipeline: Rule[];
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
    placeholder: { open: string; close: string; stripPrefixes: string[] };
    evidence: { quoteChars: string; classes: string[]; minClasses: number; entropyThreshold: number };
    trivial: { words: string[]; maskChars: string[]; wrappers: string[][]; wrapperInner: string };
    docPlaceholder: { prefixes: string[]; suffixes: string[]; separator: string };
    sync: { maxChars: number; maxDepth: number; maxNodes: number; maxKeyChars: number };
    full: { scanWindow: number; scanOverlap: number; scanCap: number };
    strict: { maxChars: number; maxDepth: number; maxNodes: number };
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
    if (rules.pipeline.length === 0 || keys.secretWords.length === 0) {
        throw new Error('redaction spec holds no rules');
    }
    return { rules, keys, algorithms };
}

const LOADED = loadSpec();
export const RULES_SPEC: RulesSpec = LOADED.rules;
export const KEYS_SPEC: KeysSpec = LOADED.keys;
export const ALGORITHMS_SPEC: AlgorithmsSpec = LOADED.algorithms;

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
