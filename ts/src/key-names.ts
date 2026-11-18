/**
 * key-names.ts — which object keys name a secret, and what a value under such
 * a key becomes. One predicate for the sync and the async JSON walkers.
 *
 * A key is split into words at separators and camelCase humps (`clientSecret`
 * → client, secret; `x-auth-token` → x, auth, token) and is secret when it
 * holds one of the word sequences as consecutive words, ends in `pass`,
 * is a lower-case run that is, ends in or starts with a secret compound
 * (`userpassword`, `secretkey`, `accesskeyid`), or is exactly one of the short
 * names. Words match as such or, for STRING values, as a plural (`tokens`);
 * `secretary`, `tokenizer` and `passwordless` do not match.
 *
 * Two verdicts, so counts are never hidden:
 *   - 'string': a string value is replaced (plural words included);
 *   - 'any': numbers are replaced too (singular secret words only, no count
 *     words): `pin: 1234` yes, `max_tokens: 100`, `prompt_tokens: 12` no.
 * Containers under a secret key are walked, never replaced wholesale.
 */
import { splitKeyWords } from './algorithms/key-words.js';
import { foldLower } from './portable.js';
import { buildReadPlaceholder, literalSegments, PLACEHOLDER_RE } from './placeholder.js';
import { ALGORITHMS_SPEC, KEYS_SPEC } from './spec.js';

/** Keys whose primitive values are structural identifiers: never scanned.
 *  Containers under these keys are still walked. Shared by both walkers. */
export const STRUCTURAL_SKIP_KEYS: ReadonlySet<string> = new Set(KEYS_SPEC.structuralSkipKeys);

/**
 * @deprecated Substring matcher of 0.1.1; it also hits `secretary` and
 * `tokenizer` and misses `x-auth-token` and `Set-Cookie`. Use
 * `isSecretKeyName`. Kept exported unchanged for existing consumers.
 */
const LEGACY = KEYS_SPEC.tsExtensions.credentialKeyRegex;
export const CREDENTIAL_KEY_RE = new RegExp(LEGACY.source, LEGACY.flags);

/** Rule id of every placeholder that was decided by a key name. */
export const KEY_CONTEXT_RULE_ID = ALGORITHMS_SPEC.ruleIds.keyContext;

const SECRET_KEY_SEQUENCES = [...KEYS_SPEC.secretWords, ...KEYS_SPEC.extraSequences];
const EXACT_SECRET_KEYS = new Set(KEYS_SPEC.exactKeys);
const JOINED_SECRET_WORDS = new Set([
    ...SECRET_KEY_SEQUENCES.filter((parts) => parts.length > 1).map((parts) => parts.join('')),
    ...KEYS_SPEC.joinedExtra,
]);
const COUNT_WORDS = new Set(KEYS_SPEC.countWords);

function matchesWord(word: string | undefined, expected: string, plural: boolean): boolean {
    return word === expected || (plural && word === `${expected}s`);
}

function startsSequence(words: string[], start: number, sequence: string[], plural: boolean): boolean {
    return sequence.every((expected, offset) => matchesWord(words[start + offset], expected, plural));
}

function isSecretWord(word: string, plural: boolean): boolean {
    const base = plural ? word.replace(/s$/, '') : word;
    if (JOINED_SECRET_WORDS.has(word) || JOINED_SECRET_WORDS.has(base)) return true;
    if (KEYS_SPEC.suffixWords.some((suffix) => base.endsWith(suffix))) return true;
    return KEYS_SPEC.prefixWords.some((prefix) => word.startsWith(prefix));
}

/** The key lower-cased with everything but `a-z0-9` dropped (U+0130 lower-cases to `i` + a mark). */
function compactKey(key: string): string {
    return foldLower(key).replace(/\u0130/g, 'i').replace(/[^a-z0-9]/g, '');
}

function matchKey(key: string, plural: boolean): boolean {
    const words = splitKeyWords(key);
    if (EXACT_SECRET_KEYS.has(compactKey(key))) return true;
    if (words[words.length - 1] === KEYS_SPEC.passLastWord) return true;
    if (words.some((word) => isSecretWord(word, plural))) return true;
    return SECRET_KEY_SEQUENCES.some((sequence) => {
        return words.some((_, start) => startsSequence(words, start, sequence, plural));
    });
}

/** True for names such as `apiKey`, `client_secret`, `DB-PASSWORD`, `x-auth-token`,
 *  `Set-Cookie`, `Proxy-Authorization`, `cardNumber`, `MYSQL_PWD`, `pin`, `tokens`. */
export function isSecretKeyName(key: string): boolean {
    return matchKey(key, true);
}

export type KeyVerdict = 'none' | 'string' | 'any';

/** What a key makes of the values below it: nothing, strings, or strings and numbers. */
export function keyVerdict(rawKey: string): KeyVerdict {
    // A key that was redacted (it held a secret) is classified without its placeholders,
    // so a second pass gives the same verdict as the first.
    const key = rawKey.includes('[REDACTED') ? literalSegments(rawKey).join(' ') : rawKey;
    if (!matchKey(key, true)) return 'none';
    if (!matchKey(key, false)) return 'string';
    return splitKeyWords(key).some((word) => COUNT_WORDS.has(word)) ? 'string' : 'any';
}

/** The stronger of two verdicts: a nested secret key never weakens the context. */
export function strongerVerdict(a: KeyVerdict, b: KeyVerdict): KeyVerdict {
    if (a === 'any' || b === 'any') return 'any';
    return a === 'string' || b === 'string' ? 'string' : 'none';
}

/**
 * The placeholder that replaces the primitive `value` under verdict `verdict`,
 * or `undefined` when it stays: no secret context, empty strings, `null`,
 * booleans, numbers outside an 'any' context, and values that already are a
 * placeholder (idempotence).
 */
export function leafPlaceholder(verdict: KeyVerdict, value: unknown): string | undefined {
    if (verdict === 'none') return undefined;
    if (typeof value === 'string') {
        if (value.length === 0 || PLACEHOLDER_RE.test(value)) return undefined;
        return buildReadPlaceholder(KEY_CONTEXT_RULE_ID);
    }
    const isNumber = typeof value === 'number' || typeof value === 'bigint';
    return isNumber && verdict === 'any' ? buildReadPlaceholder(KEY_CONTEXT_RULE_ID) : undefined;
}
