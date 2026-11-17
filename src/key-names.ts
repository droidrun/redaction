/**
 * key-names.ts — which object keys name a secret, and what a value under such
 * a key becomes. One predicate for the sync and the async JSON walkers.
 *
 * `isSecretKeyName` is the word-based matcher ported from triggers-api: a key
 * is split into words at separators and camelCase humps (`clientSecret` →
 * client, secret; `x-auth-token` → x, auth, token) and is secret when it holds
 * one of the word sequences as consecutive words, or is exactly one of the
 * short names. Words match as such or as a plural, so `secretary` and
 * `tokenizer` do not, `tokens` does, and so do `hasPassword` and
 * `passwordPolicy`.
 *
 * One predicate for every walker. `CREDENTIAL_KEY_RE` (0.1.1, substring match,
 * so it also hit `secretary` and `tokenizer`) stays exported for consumers that
 * use it themselves; the walkers use the word matcher, extended below with the
 * lower-case compounds (`userpassword`) the substring match used to catch.
 */
import { buildReadPlaceholder, PLACEHOLDER_RE } from './placeholder.js';

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
];

// Short or common as words (`pin`, `spin`, `pinned`), so only the whole key counts.
const EXACT_SECRET_KEYS = new Set(['pwd', 'otp', 'totp', 'pin', 'cvv', 'cvc', 'sig', 'sid', 'jwt']);

// The same sequences written as one lower-case run (`apikey`, `privatekey`), and a few more.
const JOINED_SECRET_WORDS = new Set([
    ...SECRET_KEY_SEQUENCES.filter((parts) => parts.length > 1).map((parts) => parts.join('')),
    'clientsecret', 'refreshtoken', 'idtoken', 'sessiontoken', 'apitoken', 'setcookie',
]);

// A lower-case run that ENDS in one of these is a compound of the secret word
// (`userpassword`, `csrftoken`); one that merely starts with it is not
// (`secretary`, `tokenizer`, `passwordless`).
const SUFFIX_SECRET_WORDS = [
    'password', 'passwd', 'passphrase', 'secret', 'token', 'apikey', 'accesskey', 'privatekey', 'credential',
];

const WORD_RE = /[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+/g;

function matchesWord(word: string | undefined, expected: string): boolean {
    return word === expected || word === `${expected}s`;
}

function startsSequence(words: string[], start: number, sequence: string[]): boolean {
    return sequence.every((expected, offset) => matchesWord(words[start + offset], expected));
}

/** True for names such as `apiKey`, `client_secret`, `DB-PASSWORD`, `x-auth-token`,
 *  `Set-Cookie`, `Proxy-Authorization`, `cardNumber`, `pin`. */
export function isSecretKeyName(key: string): boolean {
    const words = (key.match(WORD_RE) ?? []).map((word) => word.toLowerCase());
    if (EXACT_SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z0-9]/g, ''))) return true;
    const joined = words.some((word) => {
        const singular = word.replace(/s$/, '');
        return JOINED_SECRET_WORDS.has(word) || JOINED_SECRET_WORDS.has(singular) ||
            SUFFIX_SECRET_WORDS.some((suffix) => singular.endsWith(suffix));
    });
    if (joined) return true;
    return SECRET_KEY_SEQUENCES.some((sequence) => {
        return words.some((_, start) => startsSequence(words, start, sequence));
    });
}

/**
 * The placeholder that replaces `value` when it sits under key `key`, or
 * `undefined` when the value stays as it is: the key is not secret, the value
 * is empty, `null`, a boolean (no secret material), or already a placeholder
 * (idempotence). A string, number or whole object/array under a secret key is
 * replaced as a unit, whatever its shape.
 */
export function keyContextPlaceholder(key: string, value: unknown): string | undefined {
    if (!isSecretKeyName(key)) return undefined;
    if (typeof value === 'string') {
        if (value.length === 0 || PLACEHOLDER_RE.test(value)) return undefined;
        return buildReadPlaceholder(KEY_CONTEXT_RULE_ID);
    }
    const isReplaceable = typeof value === 'number' || typeof value === 'bigint' ||
        (typeof value === 'object' && value !== null);
    return isReplaceable ? buildReadPlaceholder(KEY_CONTEXT_RULE_ID) : undefined;
}
