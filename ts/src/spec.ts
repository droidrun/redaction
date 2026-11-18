/**
 * spec.ts — loads the language-neutral rule spec (`ts/spec/*.json`, a copy of the
 * repo's `spec/` written by `tools/sync-spec`), refuses to start when it does not
 * match the generated hash or holds no rules, and expands the pattern macros.
 * Nothing in `src/` restates a rule, word list or threshold: it all comes from here.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SPEC_HASH } from './spec-hash.generated.js';

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
const HASHED_FILES = ['rules.json', 'keys.json', 'algorithms.json'] as const;
const MACRO_REFERENCE = /\{\{([A-Z_]+)\}\}/g;
const MAX_MACRO_DEPTH = 8;

function readSpecFile(name: string): Buffer {
    return readFileSync(new URL(`../spec/${name}`, import.meta.url));
}

/** SHA-256 over `name NUL bytes NUL` of the three data files, in a fixed order. */
export function hashSpecFiles(read: (name: string) => Uint8Array): string {
    const hash = createHash('sha256');
    for (const name of HASHED_FILES) {
        hash.update(`${name}\0`);
        hash.update(read(name));
        hash.update('\0');
    }
    return hash.digest('hex');
}

function parse<T extends { specVersion: number }>(bytes: Buffer): T {
    const parsed = JSON.parse(bytes.toString('utf8')) as T;
    if (parsed.specVersion !== SPEC_SUPPORTED_VERSION) throw new Error('unsupported redaction spec version');
    return parsed;
}

function loadSpec(): { rules: RulesSpec; keys: KeysSpec; algorithms: AlgorithmsSpec } {
    const files = new Map(HASHED_FILES.map((name) => [name, readSpecFile(name)]));
    const read = (name: string): Uint8Array => files.get(name as (typeof HASHED_FILES)[number]) as Buffer;
    if (hashSpecFiles(read) !== SPEC_HASH) throw new Error('redaction spec does not match its hash');
    const rules = parse<RulesSpec>(read('rules.json') as Buffer);
    const keys = parse<KeysSpec>(read('keys.json') as Buffer);
    const algorithms = parse<AlgorithmsSpec>(read('algorithms.json') as Buffer);
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
