/**
 * sync-rules.ts — the deterministic, regex-only rule set, and the ONE rule
 * source of both entry points (the async path adds the upstream secretlint
 * scanners on top). It reports value ranges for: credential keywords
 * (`password=…`, also inside escaped JSON), `Bearer`/`Basic`/`Token` values,
 * secret-named URL query parameters, URL userinfo, cookie header lines, PEM
 * private keys, and known key formats (JWT, Google, xAI, OpenAI/Anthropic,
 * Stripe, GitHub, AWS key id, Slack, Mobilerun platform tokens).
 *
 * Every rule is linear-time or bounded per candidate. Only ranges leave this
 * module; it never logs or returns matched text.
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
import { placeholderEndAt } from './placeholder.js';

type Range = [number, number];

const KEYWORD_RULE_ID = 'generic-keyword';
const AUTH_RULE_ID = 'auth-header';

// Words masked in free text WITHOUT a value-evidence test (`password: hunter2`).
// Deliberately the narrow list: widening it would mask prose such as
// "token: expired". The wider keyword list (with evidence) is `patterns.ts`.
const SECRET_KEYS = SECRET_WORDS.map((parts) => parts.join('[_-]?')).join('|');
const ESCAPED_QUOTE = String.raw`(?:\\*["'])`;

/** A quoted value may hold spaces and commas; one longer than this is not
 *  searched for its closing quote but redacted to the end of the text. */
const QUOTED_VALUE_LIMIT = 1024;

// `label` + separator + opening quote (with its escape backslashes, group 1).
const QUOTED_LABEL = new RegExp(
    String.raw`\b(?:${SECRET_KEYS})\b${ESCAPED_QUOTE}?\s*[:=]\s*(\\*)(["'])`,
    'gid',
);
const UNQUOTED_PAIR = new RegExp(
    String.raw`\b(?:${SECRET_KEYS})\b${ESCAPED_QUOTE}?\s*[:=]\s*${ESCAPED_QUOTE}?` +
    String.raw`((?:[^\s,"';}\\]|\\(?![\\"']))+)`,
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
// "Missing or invalid bearer token": prose, not a credential.
const AUTH_PLAIN_WORDS = new Set([
    'token', 'tokens', 'auth', 'authentication', 'header', 'scheme', 'missing', 'invalid', 'required',
]);

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const PLATFORM_TOKEN = new RegExp(
    `srt1\\.${UUID}\\.[0-9]+\\.[A-Za-z0-9_-]{43}|` +
    `srt2\\.${UUID}\\.${UUID}\\.(?:kilo|script)\\.[0-9]+\\.[0-9a-fA-F]{64}`,
    'g',
);
const PLATFORM_KEY = /\bdr_sk_[A-Za-z0-9_-]{8,}/g;
const GITHUB_TOKEN = /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g;
const AWS_KEY_ID = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const SLACK_TOKEN = /\bxox[abposr]-[0-9A-Za-z-]{10,200}\b/g;
const STRIPE_KEY = /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/g;
// `sk-…`, `sk-proj-…`, `sk-ant-…`: needs a digit, so `sk-learn-is-a-name` stays.
const SK_KEY = /\bsk-(?:proj-|ant-[A-Za-z0-9]{1,16}-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g;
const URL_PASSWORD = /\b[A-Za-z][A-Za-z0-9+.-]{1,31}:\/\/[^\s/?#@:"'<>]{1,128}:([^\s/?#@"'<>]+)@/gd;
const COOKIE_LINE = /\b(?:Set-)?Cookie\s*:\s*((?:[^\r\n\\"]|\\(?![nr"']))+)/gdi;

const PEM_HEADER = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----/g;
const PEM_FOOTER = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----/y;
const PEM_BODY_CHAR = /[A-Za-z0-9+/=\s\\:,.-]/;
const PEM_BODY_LIMIT = 8192;

const FORMAT_RULES: ReadonlyArray<readonly [string, RegExp]> = [
    ['jwt', JWT_PATTERN],
    ['gcp-api-key', GCP_API_KEY_PATTERN],
    ['xai-api-key', XAI_API_KEY_PATTERN],
    ['platform-token', PLATFORM_TOKEN],
    ['platform-key', PLATFORM_KEY],
    ['github', GITHUB_TOKEN],
    ['aws', AWS_KEY_ID],
    ['slack', SLACK_TOKEN],
    ['stripe', STRIPE_KEY],
];

// Query parameters that carry a secret only in a URL (`code` is an ordinary
// JSON key, `?code=` is an OAuth code).
const QUERY_ONLY_KEYS = new Set(['code', 'sid', 'session', 'otp', 'pwd']);
const QUERY_KEY = /[?&]([^\s=&#?]{1,128})=/g;
const QUERY_VALUE_CHAR = /[\s&#"'<>]/;
const NESTED_VALUE_END = /[\s&#"'<>?]/;
const NESTED_VALUE_LIMIT = 4096;
const DECODE_BUDGET = 1_000_000;

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

/** The text of a candidate value, cut at the value's end, when it is not a placeholder. */
function isPlaceholderValue(text: string, start: number, end: number): boolean {
    const placeholderEnd = placeholderEndAt(text, start);
    return placeholderEnd !== -1 && placeholderEnd >= end;
}

/** Pair values: not empty, not a placeholder, not a doc mask or stand-in
 *  (`xxxx`, `****`, `undefined`, `your_key_here`). */
function realPairValues(text: string, ranges: Range[]): Range[] {
    return ranges.filter(([start, end]) => {
        if (end <= start || isPlaceholderValue(text, start, end)) return false;
        const value = text.slice(start, end);
        return !isTrivialValue(value) && !isDocPlaceholder(value);
    });
}

function nonPlaceholder(text: string, ranges: Range[]): Range[] {
    return ranges.filter(([start, end]) => end > start && !isPlaceholderValue(text, start, end));
}

/** `label=value` pairs, unquoted: value ends at whitespace or a delimiter. */
function unquotedPairs(text: string): Range[] {
    const ranges: Range[] = [];
    for (const match of text.matchAll(UNQUOTED_PAIR)) {
        const range = match.indices?.[1];
        if (range) ranges.push(trimQueryValue(text, match.index ?? 0, range));
    }
    return realPairValues(text, ranges);
}

/** Closing quote of a value that opened at `from`, or -1. `layers` is the
 *  number of escape backslashes before the opening quote (escaped JSON). */
function closingQuote(text: string, from: number, quote: string, layers: number, limit: number): number {
    for (let i = from; i < limit; i++) {
        if (text[i] !== quote) continue;
        let run = 0;
        while (i - run - 1 >= from && text[i - run - 1] === '\\') run += 1;
        const closes = layers === 0 ? run % 2 === 0 : run === layers;
        if (closes) return i - run;
    }
    return -1;
}

/** Quoted values (may hold spaces, commas, escaped quotes). An unterminated or
 *  over-long value fails closed: redacted to the end of the text. */
function quotedPairs(text: string): Range[] {
    const ranges: Range[] = [];
    const pattern = new RegExp(QUOTED_LABEL);
    for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
        const layers = (match[1] ?? '').length;
        const quote = match[2] ?? '"';
        const from = pattern.lastIndex;
        const limit = Math.min(text.length, from + QUOTED_VALUE_LIMIT);
        const close = closingQuote(text, from, quote, layers, limit);
        if (close === -1) {
            if (from < text.length) ranges.push([from, text.length]);
            break;
        }
        ranges.push([from, close]);
        pattern.lastIndex = close;
    }
    return realPairValues(text, ranges);
}

function authValues(text: string): Range[] {
    const ranges = [...matchRanges(text, BEARER, 1), ...matchRanges(text, BASIC_OR_TOKEN, 1)];
    return ranges.filter(([start, end]) => {
        const word = text.slice(start, end).toLowerCase();
        return !AUTH_PLAIN_WORDS.has(word) && !isPlaceholderValue(text, start, end);
    });
}

function skKeys(text: string): Range[] {
    return matchRanges(text, SK_KEY, 0).filter(([start, end]) => /[0-9]/.test(text.slice(start, end)));
}

function cookieLines(text: string): Range[] {
    return matchRanges(text, COOKIE_LINE, 1).filter(([start, end]) => {
        return text.slice(start, end).includes('=') && !isPlaceholderValue(text, start, end);
    });
}

/** PEM private keys: header through footer; a block without footer is redacted
 *  through the end of its body-looking run (fail closed). Also written with
 *  literal `\n` in JSON text. A header inside an already covered block is skipped. */
function pemKeys(text: string): Range[] {
    const ranges: Range[] = [];
    let covered = 0;
    for (const header of text.matchAll(PEM_HEADER)) {
        const start = header.index ?? 0;
        if (start < covered) continue;
        const bodyStart = start + header[0].length;
        const limit = Math.min(text.length, bodyStart + PEM_BODY_LIMIT);
        let bodyEnd = bodyStart;
        while (bodyEnd < limit && PEM_BODY_CHAR.test(text[bodyEnd] ?? '')) bodyEnd += 1;
        const footerAt = text.indexOf('-----END', bodyStart);
        PEM_FOOTER.lastIndex = footerAt;
        const footer = footerAt !== -1 && footerAt < bodyEnd ? PEM_FOOTER.exec(text) : null;
        covered = footer ? footerAt + footer[0].length : bodyEnd;
        ranges.push([start, covered]);
    }
    return ranges;
}

function queryKeyIsSecret(key: string): boolean {
    return isSecretKeyName(key) || QUERY_ONLY_KEYS.has(key.toLowerCase());
}

function decodeOnce(value: string): string {
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}

function hasSecretQueryParam(decoded: string): boolean {
    for (const match of decoded.matchAll(QUERY_KEY)) {
        if (queryKeyIsSecret(decodeOnce(match[1] ?? ''))) return true;
    }
    return false;
}

function valueEnd(text: string, from: number): number {
    let end = from;
    while (end < text.length && !QUERY_VALUE_CHAR.test(text[end] ?? '')) end += 1;
    return end;
}

/** Values of secret-named query parameters: the whole value (up to `&`, `#`,
 *  whitespace or a quote, however long), including a `?`/`&` inside it. A
 *  non-secret parameter whose percent-encoded value hides a secret parameter
 *  (`redirect=…%3Ftoken%3D…`) is redacted whole. */
function secretQueryValues(text: string): Range[] {
    const ranges: Range[] = [];
    const pattern = new RegExp(QUERY_KEY);
    let decodeBudget = DECODE_BUDGET;
    for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
        const valueStart = pattern.lastIndex;
        const key = decodeOnce(match[1] ?? '');
        if (queryKeyIsSecret(key)) {
            const end = valueEnd(text, valueStart);
            if (end > valueStart) ranges.push([valueStart, end]);
            pattern.lastIndex = Math.max(valueStart, end);
            continue;
        }
        if (decodeBudget <= 0) continue;
        let end = valueStart;
        while (end < text.length && end - valueStart < NESTED_VALUE_LIMIT) {
            if (NESTED_VALUE_END.test(text[end] ?? '')) break;
            end += 1;
        }
        decodeBudget -= end - valueStart;
        const raw = text.slice(valueStart, end);
        if (!raw.includes('%')) continue;
        const decoded = decodeOnce(raw);
        if (decoded !== raw && hasSecretQueryParam(`?${decoded}`)) ranges.push([valueStart, end]);
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
    add('private-key', pemKeys(text));
    add('openai', skKeys(text));
    add('url-credentials', nonPlaceholder(text, matchRanges(text, URL_PASSWORD, 1)));
    add('cookie', cookieLines(text));
    add(AUTH_RULE_ID, authValues(text));
    add(KEYWORD_RULE_ID, keywordValueRanges(text));
    add(KEYWORD_RULE_ID, quotedPairs(text));
    add(KEYWORD_RULE_ID, unquotedPairs(text));
    add(KEY_CONTEXT_RULE_ID, nonPlaceholder(text, secretQueryValues(text)));
    return dedupeRanges(hits);
}
