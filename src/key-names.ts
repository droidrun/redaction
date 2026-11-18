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
import { buildReadPlaceholder, literalSegments, PLACEHOLDER_RE } from './placeholder.js';

/** Keys whose primitive values are structural identifiers: never scanned.
 *  Containers under these keys are still walked. Shared by both walkers. */
export const STRUCTURAL_SKIP_KEYS: ReadonlySet<string> = new Set(['type', 'id']);

/**
 * @deprecated Substring matcher of 0.1.1; it also hits `secretary` and
 * `tokenizer` and misses `x-auth-token` and `Set-Cookie`. Use
 * `isSecretKeyName`. Kept exported unchanged for existing consumers.
 */
export const CREDENTIAL_KEY_RE = new RegExp(
    'password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|' +
    'private[_-]?key|client[_-]?secret|credential',
    'i',
);

/** Rule id of every placeholder that was decided by a key name. */
export const KEY_CONTEXT_RULE_ID = 'key-context';

/** The words the keyword rules mask in free text (`password=…`). */
export const SECRET_WORDS = [
    ['api', 'key'], ['access', 'token'], ['auth', 'token'], ['password'], ['secret'],
];

const SECRET_KEY_SEQUENCES = [
    ...SECRET_WORDS,
    ['token'], ['authorization'], ['cookie'], ['credential'], ['private', 'key'], ['client', 'key'],
    ['access', 'key'], ['passwd'], ['passphrase'], ['signature'], ['card', 'number'],
    ['basic', 'auth'], ['priv', 'key'], ['signing', 'key'], ['encryption', 'key'], ['master', 'key'],
    ['ssh', 'key'], ['service', 'account', 'key'], ['dsn'], ['connection', 'string'],
    ['recovery', 'code'],
];

// Short or common as words (`pin`, `spin`, `auth`, `passThrough`), so only the
// whole key counts. `sid` is NOT here (Twilio ids); `code` and `sid` are
// secret in a URL query only (`sync-rules.ts`).
const EXACT_SECRET_KEYS = new Set([
    'pwd', 'otp', 'totp', 'pin', 'cvv', 'cvc', 'sig', 'jwt', 'pass', 'auth',
]);

// The same sequences written as one lower-case run (`apikey`, `privatekey`), and a few more.
const JOINED_SECRET_WORDS = new Set([
    ...SECRET_KEY_SEQUENCES.filter((parts) => parts.length > 1).map((parts) => parts.join('')),
    'clientsecret', 'refreshtoken', 'idtoken', 'sessiontoken', 'apitoken', 'setcookie', 'privkey',
]);

// A lower-case run that ENDS in one of these is a compound (`userpassword`,
// `csrftoken`); one that merely starts with the word is not (`secretary`).
const SUFFIX_SECRET_WORDS = [
    'password', 'passwd', 'passphrase', 'secret', 'token', 'apikey', 'accesskey', 'privatekey', 'credential',
    'pwd',
];

// A lower-case run that STARTS with one of these is a compound (`secretkeybase`,
// `accesskeyid`, `privatekeypem`, `apikeyvalue`).
const PREFIX_SECRET_WORDS = [
    'secretkey', 'accesskey', 'privatekey', 'apikey', 'clientsecret', 'authtoken', 'accesstoken',
    'refreshtoken', 'signingkey', 'encryptionkey', 'masterkey', 'sshkey', 'serviceaccountkey',
    'connectionstring', 'recoverycodes', 'basicauth', 'privkey',
];

// Words that make a number a count or a setting, never the secret itself.
const COUNT_WORDS = new Set([
    'count', 'limit', 'max', 'min', 'total', 'usage', 'used', 'budget', 'num', 'size', 'length', 'ttl',
    'expires', 'expiry', 'age', 'rate', 'quota', 'remaining',
]);

const WORD_RE = /[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+/g;

function matchesWord(word: string | undefined, expected: string, plural: boolean): boolean {
    return word === expected || (plural && word === `${expected}s`);
}

function startsSequence(words: string[], start: number, sequence: string[], plural: boolean): boolean {
    return sequence.every((expected, offset) => matchesWord(words[start + offset], expected, plural));
}

function isSecretWord(word: string, plural: boolean): boolean {
    const base = plural ? word.replace(/s$/, '') : word;
    if (JOINED_SECRET_WORDS.has(word) || JOINED_SECRET_WORDS.has(base)) return true;
    if (SUFFIX_SECRET_WORDS.some((suffix) => base.endsWith(suffix))) return true;
    return PREFIX_SECRET_WORDS.some((prefix) => word.startsWith(prefix));
}

function matchKey(key: string, plural: boolean): boolean {
    const words = (key.match(WORD_RE) ?? []).map((word) => word.toLowerCase());
    if (EXACT_SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z0-9]/g, ''))) return true;
    const last = words[words.length - 1];
    if (last === 'pass') return true;
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
    const words = (key.match(WORD_RE) ?? []).map((word) => word.toLowerCase());
    return words.some((word) => COUNT_WORDS.has(word)) ? 'string' : 'any';
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
