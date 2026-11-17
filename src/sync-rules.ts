/**
 * sync-rules.ts — the deterministic, regex-only rule set. It reports value
 * ranges for: credential keywords (`password=…`), `Bearer`/`Basic`/`Token`
 * authorization values, secret-named URL query parameters, and known key
 * formats (JWT, Google, xAI, GitHub, AWS key id, Slack, Mobilerun platform
 * tokens).
 *
 * This is the whole rule set of the sync entry (`redact-sync.ts`) and the
 * first half of the async one (`detectSecrets` adds the secretlint scanners).
 * Patterns shared with the secretlint rules come from `patterns.ts`.
 * Only ranges leave this module; it never logs or returns matched text.
 */
import { dedupeRanges, type Hit } from './hits.js';
import { isSecretKeyName, KEY_CONTEXT_RULE_ID, SECRET_WORDS } from './key-names.js';
import {
    GCP_API_KEY_PATTERN,
    isDocPlaceholder,
    isTrivialValue,
    JWT_PATTERN,
    keywordValueRanges,
    trimQueryValue,
    XAI_API_KEY_PATTERN,
} from './patterns.js';
import { PLACEHOLDER_ANYWHERE_RE } from './placeholder.js';

type Range = [number, number];

// Rule ids use the short form `shortenRuleId` would give the secretlint rule
// of the same finding, so sync and async placeholders agree.
const KEYWORD_RULE_ID = 'generic-keyword';
const AUTH_RULE_ID = 'auth-header';

// Words masked in free text WITHOUT a value-evidence test (`password: hunter2`).
// Deliberately the narrow list: widening it would mask prose such as
// "token: expired". The wider keyword list (with evidence) is `patterns.ts`.
const SECRET_KEYS = SECRET_WORDS.map((parts) => parts.join('[_-]?')).join('|');
const NOT_A_PLACEHOLDER = String.raw`(?!\[REDACTED(?::[^\]\s]*)?\])`;

// Quoted values first (they may contain spaces, commas, escaped quotes). The
// value is bounded (1024) so a run of unterminated `password="` cannot make
// every occurrence rescan the rest of the text; the unquoted rule below
// still catches the first token of an over-long or unterminated value.
const QUOTED_PAIR = new RegExp(
    String.raw`(["']?)\b(?:${SECRET_KEYS})\b\1\s*[:=]\s*(["'])((?:\\.|(?!\2)[^\\]){0,1024})\2`,
    'gid',
);
const UNQUOTED_PAIR = new RegExp(
    String.raw`\b(?:${SECRET_KEYS})\b["']?\s*[:=]\s*["']?${NOT_A_PLACEHOLDER}([^\s,"';}]+)`,
    'gid',
);

const BEARER = /\bBearer\s+([A-Za-z0-9._~+/=-]+)/gid;
// Basic and Token are also ordinary words, so their value must look like a
// credential: at least 8 characters and not a plain lower-case or Capitalized
// word ("Token expired", "Basic information" stay).
const BASIC_OR_TOKEN = new RegExp(
    String.raw`\b(?:[Bb]asic|BASIC|[Tt]oken|TOKEN)\s+(?=[A-Za-z0-9+/=._~-]{8,})` +
    String.raw`(?![a-z]+\b)(?![A-Z][a-z]+\b)([A-Za-z0-9+/=._~-]+)`,
    'gd',
);

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const PLATFORM_TOKEN = new RegExp(
    `srt1\\.${UUID}\\.[0-9]+\\.[A-Za-z0-9_-]{43}|` +
    `srt2\\.${UUID}\\.${UUID}\\.(?:kilo|script)\\.[0-9]+\\.[0-9a-fA-F]{64}`,
    'g',
);
const GITHUB_TOKEN = /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g;
const AWS_KEY_ID = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const SLACK_TOKEN = /\bxox[abposr]-[0-9A-Za-z-]{10,200}\b/g;

const QUERY_PARAM = /[?&]([^\s=&#?]{1,128})=([^\s&#"'<>]{1,4096})/gd;

const FORMAT_RULES: ReadonlyArray<readonly [string, RegExp]> = [
    ['jwt', JWT_PATTERN],
    ['gcp-api-key', GCP_API_KEY_PATTERN],
    ['xai-api-key', XAI_API_KEY_PATTERN],
    ['platform-token', PLATFORM_TOKEN],
    ['github', GITHUB_TOKEN],
    ['aws', AWS_KEY_ID],
    ['slack', SLACK_TOKEN],
];

function matchRanges(text: string, pattern: RegExp, group: number): Range[] {
    const ranges: Range[] = [];
    for (const match of text.matchAll(pattern)) {
        const range = match.indices?.[group] ?? (group === 0 && match.index !== undefined
            ? [match.index, match.index + match[0].length]
            : undefined);
        if (range) ranges.push([range[0], range[1]]);
    }
    return ranges;
}

/** Like `matchRanges`, for `label=value` pairs that may sit in a URL query string. */
function pairRanges(text: string, pattern: RegExp, group: number): Range[] {
    const ranges: Range[] = [];
    for (const match of text.matchAll(pattern)) {
        const range = match.indices?.[group];
        if (range) ranges.push(trimQueryValue(text, match.index ?? 0, range));
    }
    return ranges;
}

function nonEmptyValues(text: string, ranges: Range[]): Range[] {
    return ranges.filter(([start, end]) => end > start && !isPlaceholder(text.slice(start, end)));
}

/** Pair values: not empty, not a placeholder, not a doc mask or stand-in
 *  (`xxxx`, `****`, `undefined`, `your_key_here`). */
function realPairValues(text: string, ranges: Range[]): Range[] {
    return nonEmptyValues(text, ranges).filter(([start, end]) => {
        const value = text.slice(start, end);
        return !isTrivialValue(value) && !isDocPlaceholder(value);
    });
}

function isPlaceholder(value: string): boolean {
    const match = PLACEHOLDER_ANYWHERE_RE.exec(value);
    return match !== null && match.index === 0;
}

function decodeKey(key: string): string {
    try {
        return decodeURIComponent(key);
    } catch {
        return key;
    }
}

function secretQueryValues(text: string): Range[] {
    const ranges: Range[] = [];
    for (const match of text.matchAll(QUERY_PARAM)) {
        const key = match[1] ?? '';
        const valueRange = match.indices?.[2];
        if (!valueRange || !isSecretKeyName(decodeKey(key))) continue;
        ranges.push([valueRange[0], valueRange[1]]);
    }
    return ranges;
}

/** Every secret range the deterministic rules find in `text`, overlapping
 *  ranges merged. Earlier rules below win equal starts (the merged hit keeps
 *  the first rule's id). */
export function detectSyncHits(text: string): Hit[] {
    const hits: Hit[] = [];
    const add = (ruleId: string, ranges: Range[]): void => {
        for (const range of ranges) hits.push({ ruleId, range });
    };
    for (const [ruleId, pattern] of FORMAT_RULES) {
        add(ruleId, matchRanges(text, pattern, 0));
    }
    add(AUTH_RULE_ID, matchRanges(text, BEARER, 1));
    add(AUTH_RULE_ID, matchRanges(text, BASIC_OR_TOKEN, 1));
    add(KEYWORD_RULE_ID, keywordValueRanges(text));
    add(KEYWORD_RULE_ID, realPairValues(text, pairRanges(text, QUOTED_PAIR, 3)));
    add(KEYWORD_RULE_ID, realPairValues(text, pairRanges(text, UNQUOTED_PAIR, 1)));
    add(KEY_CONTEXT_RULE_ID, nonEmptyValues(text, secretQueryValues(text)));
    return dedupeRanges(hits);
}
