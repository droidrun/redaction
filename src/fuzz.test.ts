/**
 * fuzz.test.ts — seeded property tests (no new dependency): 3000+ generated
 * cases per family. Properties:
 *   1. no leak: an injected fake marker, placed in a context a rule must
 *      catch, never survives redaction;
 *   2. idempotent: redact(redact(x)) == redact(x);
 *   3. round trip: restoreRedacted(redact(x), x) deep-equals x for JSON, also
 *      after array items were deleted, inserted and reordered (ids), with no
 *      conflicts.
 * Markers are placed in values, under secret-named keys, inside containers
 * under `type`/`id`, in object keys, in escaped JSON (one and two layers), URL
 * userinfo, nested and percent-encoded query strings, cookies and `dr_sk_` keys.
 * Deterministic: the seed is fixed; a failure prints the case index and input.
 */
import { describe, expect, test } from 'bun:test';
import {
    redactJsonValue,
    redactJsonValueSync,
    redactText,
    redactTextSync,
    restoreRedacted,
} from './index.js';
import { setOwnKey } from './own-key.js';

const SYNC_CASES = 3_000;
const ASYNC_CASES = 600;

function mulberry32(seed: number): () => number {
    let a = seed;
    return () => {
        a = (a + 0x6d2b79f5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

type Rng = ReturnType<typeof mulberry32>;
const pick = <T>(rng: Rng, items: readonly T[]): T => items[Math.floor(rng() * items.length)] as T;
const BASE62 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

/** A fake secret with upper, lower, digit and `_`: it has the evidence every rule asks for. */
function marker(rng: Rng): string {
    let body = '';
    for (let i = 0; i < 14; i++) body += pick(rng, [...BASE62]);
    return `Zq9${body}_x`;
}

const WORDS = [
    'the', 'deploy', 'failed', 'user', 'login', 'ok', 'retry', 'secretary', 'passwordless', 'tokenizer',
    'Token', 'expired', 'Basic', 'information', 'bearer', 'auth', 'key', 'id', 'status', 'name', 'value',
    'https://example.test/path?page=2&sort=asc', 'a-b-c', 'x_y_z', 'ünïcödé', '日本語', '😀',
    '{}', '[]',
    '[REDACTED]', '[REDACTED:key-context]', '[REDACTED:generic-keyword:4dor]', '"', "'", '\\', '\n', ':',
    '=', ',',
    'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB', '3fa85f64-5717-4562-b3fc-2c963f66afa6',
];
const SEPARATORS = [' ', ' ', '\n', ', ', '; ', '\t', ' | '] as const;

const SECRET_KEYS = [
    'password', 'apiKey', 'api_key', 'client_secret', 'x-auth-token', 'Authorization', 'Set-Cookie',
    'accessToken',
    'refresh_token', 'privateKey', 'DB_PASSWORD', 'sessionToken', 'secret', 'token', 'cookie', 'passphrase',
];
const NEUTRAL_KEYS = [
    'name', 'url', 'prompt', 'items', 'body', 'headers', 'status', 'secretary', 'tokenizer', 'note',
];

/** Text contexts a rule must catch, each embedding the marker `m`. */
const CONTEXTS: ReadonlyArray<(m: string) => string> = [
    (m) => `password=${m}`,
    (m) => `password: ${m}`,
    (m) => `password="${m}"`,
    (m) => `api_key=${m},next=2`,
    (m) => `{"client_secret":"${m}","ok":true}`,
    (m) => `session_token: ${m}`,
    (m) => `Authorization: Bearer ${m}`,
    (m) => `Authorization: Basic ${m}`,
    (m) => `Authorization: Token ${m}`,
    (m) => `https://example.test/cb?token=${m}&x=1`,
    (m) => `https://example.test/v1?x=1&sig=${m}`,
    (m) => `AWS_SECRET_ACCESS_KEY=${m}`,
    (m) => `{"access_token": "${m}"}`,
    (m) => `{\\"password\\":\\"${m}\\",\\"ok\\":1}`,
    (m) => `{\\\\\\"client_secret\\\\\\":\\\\\\"${m}\\\\\\"}`,
    (m) => `postgres://user:${m}@db.example.test:5432/app`,
    (m) => `https://x.test/cb?redirect=https://y.test/?token=${m}&z=1`,
    (m) => `https://x.test/cb?redirect=https%3A%2F%2Fy.test%2F%3Ftoken%3D${m}&z=1`,
    (m) => `Cookie: sid=${m}; theme=dark`,
    (m) => `key dr_sk_${m} used`,
];

function noise(rng: Rng, count: number): string[] {
    return Array.from({ length: count }, () => pick(rng, WORDS));
}

function joinFragments(rng: Rng, fragments: string[]): string {
    return fragments.map((fragment, i) => (i === 0 ? fragment : pick(rng, SEPARATORS) + fragment)).join('');
}

function textCase(rng: Rng): { input: string; markers: string[] } {
    const markers: string[] = [];
    const fragments = noise(rng, Math.floor(rng() * 8));
    const contexts = 1 + Math.floor(rng() * 3);
    for (let i = 0; i < contexts; i++) {
        const m = marker(rng);
        markers.push(m);
        fragments.splice(Math.floor(rng() * (fragments.length + 1)), 0, pick(rng, CONTEXTS)(m));
    }
    return { input: joinFragments(rng, fragments), markers };
}

function jsonLeaf(rng: Rng): unknown {
    return pick(rng, [
        () => pick(rng, WORDS), () => Math.floor(rng() * 1e6), () => rng() < 0.5, () => null, () => '',
        () => joinFragments(rng, noise(rng, 3)),
    ])();
}

/** An array of objects with unique ids, each holding a secret next to a url. */
function records(rng: Rng, markers: string[]): unknown[] {
    const length = 1 + Math.floor(rng() * 5);
    return Array.from({ length }, (_, n) => {
        const m = marker(rng);
        markers.push(m);
        return { id: `rec-${n}`, url: `https://h${n}.example.test/hook`, token: m, note: `n${n}` };
    });
}

function jsonValue(rng: Rng, depth: number, markers: string[]): unknown {
    const roll = rng();
    if (depth <= 0 || roll < 0.25) return jsonLeaf(rng);
    if (roll < 0.35) {
        const length = Math.floor(rng() * 4);
        return Array.from({ length }, () => jsonValue(rng, depth - 1, markers));
    }
    if (roll < 0.45) return records(rng, markers);
    const out: Record<string, unknown> = {};
    const size = 1 + Math.floor(rng() * 4);
    for (let i = 0; i < size; i++) {
        const key = pick(rng, [...NEUTRAL_KEYS, ...SECRET_KEYS, '__proto__', 'constructor', 'type', 'id']);
        const isSecretNamed = SECRET_KEYS.includes(key);
        const isStructural = key === 'type' || key === 'id';
        if (isStructural && rng() < 0.3) {
            // A container under type/id is walked, so a marker inside it must go too.
            const m = marker(rng);
            markers.push(m);
            setOwnKey(out, key, { inner: pick(rng, CONTEXTS)(m), list: [pick(rng, CONTEXTS)(m)] });
        } else if (isStructural) {
            setOwnKey(out, key, jsonLeaf(rng));
        } else if (isSecretNamed && rng() < 0.6) {
            const m = marker(rng);
            markers.push(m);
            setOwnKey(out, key, pick(rng, [() => m, () => ({ nested: m }), () => [m, 'x']])());
        } else if (rng() < 0.2) {
            const m = marker(rng);
            markers.push(m);
            setOwnKey(out, key, pick(rng, CONTEXTS)(m));
        } else {
            setOwnKey(out, key, jsonValue(rng, depth - 1, markers));
        }
    }
    return out;
}

function jsonCase(rng: Rng): { input: unknown; markers: string[] } {
    const markers: string[] = [];
    const input = jsonValue(rng, 4, markers);
    return { input, markers };
}

function hasUniqueIds(items: unknown[]): boolean {
    const ids = items.map((item) => (item as { id?: unknown } | null)?.id);
    const isRecordWithId = items.every((item) => typeof item === 'object' && item !== null);
    return isRecordWithId && ids.every((id) => typeof id === 'string') && new Set(ids).size === ids.length;
}

/** Delete, reorder and append items of id-keyed arrays, in the redacted and the stored value alike. */
function mutateBoth(redacted: unknown, stored: unknown, rng: Rng): [unknown, unknown] {
    if (Array.isArray(redacted) && Array.isArray(stored)) {
        const order = redacted.map((_, i) => i).filter(() => rng() < 0.8).sort(() => rng() - 0.5);
        const canMutate = hasUniqueIds(redacted);
        const indexes = canMutate ? order : redacted.map((_, i) => i);
        const pairs = indexes.map((i) => mutateBoth(redacted[i], stored[i], rng));
        const outRedacted = pairs.map(([r]) => r);
        const outStored = pairs.map(([, x]) => x);
        if (canMutate) {
            const added = { id: 'added', url: 'https://new.example.test', token: 'brand-new-value' };
            outRedacted.push(added);
            outStored.push(added);
        }
        return [outRedacted, outStored];
    }
    const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;
    if (!Array.isArray(redacted) && isRecord(redacted) && isRecord(stored)) {
        const outRedacted: Record<string, unknown> = {};
        const outStored: Record<string, unknown> = {};
        for (const key of Object.keys(redacted)) {
            const [r, x] = mutateBoth(redacted[key], stored[key], rng);
            setOwnKey(outRedacted, key, r);
            setOwnKey(outStored, key, x);
        }
        return [outRedacted, outStored];
    }
    return [redacted, stored];
}

function leaked(output: unknown, markers: string[]): string | undefined {
    const serialised = typeof output === 'string' ? output : JSON.stringify(output);
    return markers.find((m) => serialised.includes(m));
}

/** Where in the output the marker survived (the context, not the secret). */
function around(output: unknown, found: string): string {
    const serialised = typeof output === 'string' ? output : JSON.stringify(output);
    const at = serialised.indexOf(found);
    return serialised.slice(Math.max(0, at - 60), at + found.length + 20);
}

describe('sync path', () => {
    test(`${SYNC_CASES} text cases: no leak, idempotent`, () => {
        const rng = mulberry32(0x5eed01);
        for (let i = 0; i < SYNC_CASES; i++) {
            const { input, markers } = textCase(rng);
            const once = redactTextSync(input).text;
            const hit = leaked(once, markers);
            if (hit !== undefined) throw new Error(`case ${i}: marker survived: ${around(once, hit)}`);
            const twice = redactTextSync(once).text;
            if (twice !== once) throw new Error(`case ${i}: not idempotent for ${JSON.stringify(input)}`);
        }
    });

    test(`${SYNC_CASES} JSON cases: no leak, idempotent, round trip`, () => {
        const rng = mulberry32(0x5eed02);
        for (let i = 0; i < SYNC_CASES; i++) {
            const { input, markers } = jsonCase(rng);
            const once = redactJsonValueSync(input);
            const hit = leaked(once, markers);
            if (hit !== undefined) throw new Error(`case ${i}: marker survived: ${around(once, hit)}`);
            const twice = redactJsonValueSync(once);
            expect(twice).toEqual(once);
            expect(restoreRedacted(once, input)).toEqual({ value: input, conflicts: [] });
            const [changed, expected] = mutateBoth(once, input, rng);
            const restored = restoreRedacted(changed, expected);
            if (restored.conflicts.length > 0) throw new Error(`case ${i}: conflicts ${restored.conflicts}`);
            expect(restored.value).toEqual(expected);
        }
    });

    test(`${SYNC_CASES} object-key cases: no leak, idempotent`, () => {
        const rng = mulberry32(0x5eed06);
        for (let i = 0; i < SYNC_CASES; i++) {
            const m = marker(rng);
            const key = pick(rng, CONTEXTS)(m);
            const once = redactJsonValueSync({ [key]: 1, nested: { [key]: [{ [key]: 'x' }] } });
            const hit = leaked(once, [m]);
            if (hit !== undefined) throw new Error(`case ${i}: marker survived: ${around(once, hit)}`);
            expect(redactJsonValueSync(once)).toEqual(once);
        }
    });

    test('sync never throws, whatever the input', () => {
        const rng = mulberry32(0x5eed03);
        for (let i = 0; i < SYNC_CASES; i++) {
            const length = Math.floor(rng() * 60);
            const text = Array.from({ length }, () => String.fromCharCode(rng() * 0xffff)).join('');
            expect(() => redactTextSync(text)).not.toThrow();
        }
    });
});

describe('async path', () => {
    test(`${ASYNC_CASES} text cases: no leak, idempotent`, async () => {
        const rng = mulberry32(0x5eed04);
        for (let i = 0; i < ASYNC_CASES; i++) {
            const { input, markers } = textCase(rng);
            const once = (await redactText(input)).text;
            const hit = leaked(once, markers);
            if (hit !== undefined) throw new Error(`case ${i}: marker survived: ${around(once, hit)}`);
            const twice = (await redactText(once)).text;
            if (twice !== once) throw new Error(`case ${i}: not idempotent for ${JSON.stringify(input)}`);
        }
    });

    test(`${ASYNC_CASES} JSON cases: no leak, idempotent, round trip`, async () => {
        const rng = mulberry32(0x5eed05);
        for (let i = 0; i < ASYNC_CASES; i++) {
            const { input, markers } = jsonCase(rng);
            const once = await redactJsonValue(input, { hits: [] });
            const hit = leaked(once, markers);
            if (hit !== undefined) throw new Error(`case ${i}: marker survived: ${around(once, hit)}`);
            expect(await redactJsonValue(once, { hits: [] })).toEqual(once);
            expect(restoreRedacted(once, input)).toEqual({ value: input, conflicts: [] });
        }
    });
});
