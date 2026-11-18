/**
 * Probes of what the JSON corpus cannot hold: options (`last4`, `detect`, `onEvent`), failure paths,
 * values built in code (Error, Date, typed arrays, cycles, bigint, functions, ...), the exported
 * constants and helpers. Each probe returns a JSON-safe description (`encode`) of what the package
 * does; the recorder runs them against the unchanged package, the golden test against the current
 * code, and both results must be equal. The probes only use the 0.2.0 public API.
 */

export type Api = {
    detectSecrets: (text: string, opts?: object) => Promise<unknown>;
    redactText: (text: string, opts?: object) => Promise<{ text: string; hits: unknown[] }>;
    redactJsonValue: (value: unknown, stats: { hits: unknown[] }, opts?: object) => Promise<unknown>;
    redactTextSync: (text: string, opts?: object) => { text: string; hits: unknown[] };
    redactJsonValueSync: (value: unknown, opts?: object) => unknown;
    restoreRedacted: (incoming: unknown, stored: unknown, opts?: object) => unknown;
    buildPlaceholder: (ruleId: string, matched: string) => string;
    buildReadPlaceholder: (ruleId: string) => string;
    shortenRuleId: (ruleId: string) => string;
    isSecretKeyName: (key: string) => boolean;
    PLACEHOLDER_RE: RegExp;
    CREDENTIAL_KEY_RE: RegExp;
    STRUCTURAL_SKIP_KEYS: ReadonlySet<string>;
};

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** A JSON-safe, order-preserving description of any value (tags for what JSON cannot hold). */
export function encode(value: unknown, seen: unknown[] = []): Json {
    if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
    if (typeof value === 'number') {
        const special = Number.isNaN(value) || !Number.isFinite(value) || Object.is(value, -0);
        return special ? { $: 'number', v: Object.is(value, -0) ? '-0' : String(value) } : value;
    }
    if (value === undefined) return { $: 'undefined' };
    if (typeof value === 'bigint') return { $: 'bigint', v: value.toString() };
    if (typeof value === 'symbol') return { $: 'symbol' };
    if (typeof value === 'function') return { $: 'function' };
    if (seen.includes(value)) return { $: 'cycle' };
    const path = [...seen, value];
    if (value instanceof Date)
        return { $: 'date', v: Number.isNaN(value.getTime()) ? 'invalid' : value.toISOString() };
    if (value instanceof RegExp) return { $: 'regexp', source: value.source, flags: value.flags };
    if (value instanceof Map) {
        return { $: 'map', e: [...value].map(([k, v]) => [encode(k, path), encode(v, path)]) };
    }
    if (value instanceof Set) return { $: 'set', e: [...value].map((v) => encode(v, path)) };
    if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
        const bytes = new Uint8Array(value instanceof ArrayBuffer ? value : value.buffer);
        return { $: 'binary', name: value.constructor.name, v: [...bytes.slice(0, 16)] };
    }
    if (Array.isArray(value)) {
        const items = Array.from({ length: value.length }, (_, i) => {
            return i in value ? encode(value[i], path) : { $: 'hole' };
        });
        return { $: 'array', e: items };
    }
    const proto = Object.getPrototypeOf(value) as { constructor?: { name?: string } } | null;
    const entries = Object.keys(value as object).map((key) => {
        return [key, encode((value as Record<string, unknown>)[key], path)];
    });
    return { $: 'object', ctor: proto === null ? 'null' : (proto.constructor?.name ?? '?'), e: entries };
}

async function capture(run: () => unknown): Promise<Json> {
    try {
        return { ok: encode(await run()) };
    } catch (error) {
        return { threw: error instanceof Error ? error.constructor.name : typeof error };
    }
}

async function drain(): Promise<void> {
    for (let i = 0; i < 3; i++) await new Promise((resolve) => setTimeout(resolve, 0));
}

const SECRET = 'password=Zq9abcDEF123ghi_x';
const LONG_SECRETS = [
    'password: S0mmer2026!xTr0ub4dor',
    'api_key=Zq9abcDEF123ghiJKL456mno',
    'Authorization: Bearer Zq9abcDEF123ghiJKL456',
    'token=short1A',
    `password=${'Zq9[x]]'.repeat(3)}`,
    `password=Zq9abcDEF123ghi_[x]`,
    `password=Zq9abcDEF123ghi]]]]`,
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c',
    'postgres://user:Zq9s3cretValue_x@db.example.test:5432/app',
    `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEz`,
    'x ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234 y',
];

type Probe = (api: Api) => Promise<unknown> | unknown;

function asyncText(api: Api, text: string, opts?: object): Promise<Json> {
    return capture(async () => {
        const result = await api.redactText(text, opts);
        return { text: result.text, hits: result.hits };
    });
}

function asyncJson(api: Api, value: unknown, opts?: object): Promise<Json> {
    return capture(async () => {
        const stats = { hits: [] as unknown[] };
        const out = await api.redactJsonValue(value, stats, opts);
        return { out, hits: stats.hits };
    });
}

function syncJson(api: Api, value: unknown, opts?: object): Promise<Json> {
    return capture(() => {
        const stats = { hits: [] as unknown[] };
        const out = api.redactJsonValueSync(value, { ...opts, stats });
        return { out, hits: stats.hits };
    });
}

async function events(api: Api, text: string, opts: object): Promise<Json> {
    const seen: Array<[string, unknown]> = [];
    const result = await capture(async () => {
        const out = await api.redactText(text, {
            ...opts,
            onEvent: (name: string, attrs: unknown) => void seen.push([name, attrs]),
        });
        return { text: out.text.length > 200 ? out.text.length : out.text, hits: out.hits };
    });
    await drain();
    return { result, events: encode(seen) };
}

function circular(): unknown {
    const root: Record<string, unknown> = { a: 1, token: 'Zq9abcDEF123ghi_x' };
    root.self = root;
    root.list = [root, { back: root }];
    return root;
}

function errorValue(message: string, name?: string): Error {
    const error = new Error(message);
    if (name !== undefined) error.name = name;
    error.stack = `${error.name}: ${message}\n    at frame`;
    return error;
}

class Holder {
    password = 'Zq9abcDEF123ghi_x';
    note = 'hello';
}

function weirdValues(): Record<string, () => unknown> {
    return {
        error: () => ({ err: errorValue(`boom ${SECRET}`) }),
        errorRoot: () => errorValue(`boom ${SECRET}`, 'CustomError'),
        errorUnderKey: () => ({ password: errorValue('x') }),
        toJson: () => ({ toJSON: () => ({ token: 'abc', ok: 1, text: SECRET }) }),
        toJsonRoot: () => ({ toJSON: () => `x ${SECRET}` }),
        toJsonThrows: () => ({
            n: {
                toJSON: () => {
                    throw new Error('no');
                },
            },
        }),
        toJsonSelf: () => {
            const value: Record<string, unknown> = { a: 'plain value 1' };
            value.toJSON = () => value;
            return value;
        },
        date: () => ({ d: new Date(0), password: new Date(0), list: [new Date(86_400_000)] }),
        invalidDate: () => ({ d: new Date(Number.NaN) }),
        typedArrays: () => ({
            u8: new Uint8Array([1, 2, 3]),
            f64: new Float64Array(2),
            buf: new ArrayBuffer(4),
        }),
        view: () => ({ v: new DataView(new ArrayBuffer(2)), password: new Uint8Array(2) }),
        buffer: () => ({ b: Buffer.from('hello') }),
        map: () => ({ m: new Map([['password', 'Zq9abcDEF123ghi_x']]) }),
        set: () => ({ s: new Set(['Zq9abcDEF123ghi_x']) }),
        cycle: () => circular(),
        arrayCycle: () => {
            const list: unknown[] = ['a'];
            list.push(list);
            return list;
        },
        bigint: () => ({ pin: 12n, max_tokens: 5n, n: 10n, big: 2n ** 80n, password: 7n, tokens: [3n] }),
        undefinedValues: () => ({ a: undefined, password: undefined, list: [undefined, 'x'] }),
        undefinedRoot: () => undefined,
        nullRoot: () => null,
        functions: () => ({ f: () => 1, password: () => 2, list: [() => 3] }),
        symbols: () => ({ s: Symbol('x'), password: Symbol('y') }),
        instance: () => new Holder(),
        instanceNested: () => ({ h: new Holder(), list: [new Holder()] }),
        nullProto: () =>
            Object.assign(Object.create(null) as object, { password: 'Zq9abcDEF123ghi_x', ok: 1 }),
        throwingGetter: () =>
            Object.defineProperty({ ok: 1 }, 'bad', {
                enumerable: true,
                get: () => {
                    throw new Error('getter');
                },
            }),
        sparse: () => [1, , 3],
        arrayProps: () => Object.assign(['a b c d e f g h'], { extra: SECRET }),
        specialNumbers: () => ({
            a: Number.NaN,
            b: Number.POSITIVE_INFINITY,
            c: -0,
            pin: Number.NaN,
            password: -0,
        }),
        boxed: () => ({
            s: new String('x'),
            n: new Number(5),
            b: new Boolean(true),
            password: new String('y'),
        }),
        proto: () => JSON.parse('{"__proto__": {"password": "Zq9abcDEF123ghi_x"}, "constructor": "x"}'),
        nonStringKeysHuge: () => ({ 4294967295: 'a', 4294967294: 'b', 1: 'c', '01': 'd', '-1': 'e' }),
        deep: () => {
            let value: unknown = { password: 'Zq9abcDEF123ghi_x' };
            for (let i = 0; i < 70; i++) value = { child: value };
            return value;
        },
    };
}

const CHECKED_KEYS = [
    'password',
    'apiKey',
    'API_KEY',
    'APIKey',
    'x-auth-token',
    'Set-Cookie',
    'sessionToken',
    'userpassword',
    'secretary',
    'tokenizer',
    'passwordless',
    'pin',
    'pİn',
    'pKn',
    'paſſword',
    'tokén',
    'TOKEN',
    'tokens',
    'max_tokens',
    'cardNumber',
    'card_number',
    'cardnumber',
    'recoveryCodes',
    'connectionString',
    'serviceAccountKey',
    'service_account_key',
    'masterKey',
    'ssh-key',
    'dsn',
    'DSN',
    'sig',
    'signature',
    'jwt',
    'auth',
    'pass',
    'Pass',
    'bypass',
    'passThrough',
    'accessKeyId',
    'secretKeyBase',
    'privateKeyPem',
    'x_pwd',
    'MYSQL_PWD',
    'clientSecret',
    'client_secrets',
    'refreshToken',
    'idToken',
    'ID_TOKEN',
    'apitoken',
    'basicAuth',
    'basic-auth',
    'Authorization',
    'Proxy-Authorization',
    'cookie',
    'cookies',
    'Cookie2',
    'credential',
    'credentials',
    'passphrase',
    'passwd',
    'otp',
    'totp',
    'cvv',
    'cvc',
    '',
    ' ',
    '___',
    '123',
    'ÜberToken',
    'A',
    'AB',
    'ABc',
    'aBC',
    'ABCdef',
    'tokenABC',
    'TOKENabc',
    'token1',
    '1token',
    'to-ken',
    'to_ken',
    'tok.en',
];

const PLACEHOLDER_STRINGS = [
    '[REDACTED]',
    '[REDACTED:aws]',
    '[REDACTED:aws:ab12]',
    '[REDACTED:aws:ab 1]',
    '[REDACTED:aws:]',
    '[REDACTED:]',
    '[REDACTED::x]',
    '[REDACTED:a b]',
    '[REDACTED:a:b:c]',
    '[REDACTED:a:[x]]',
    '[REDACTED:a:x]y]',
    'x[REDACTED]',
    '[REDACTED]x',
    ' [REDACTED]',
    '[REDACTED] ',
    '[REDACTED]\n',
    '[REDACTED]\r',
    '[REDACTED] ',
    '[REDACTED] ',
    '[REDACTED]\n\n',
    '[REDACTED]\r\n',
    '[REDACTED] ',
    '[REDACTED:a]\n',
    '[REDACTED:a:b] ',
    '[REDACTED:a\n]',
    '[redacted]',
    '[REDACTED:é]',
    '[REDACTED:😀]',
    '[REDACTED:a:😀]',
];

export const PROBES: Record<string, Probe> = {
    exportsPlaceholderRe: (api) => ({
        flags: api.PLACEHOLDER_RE.flags,
        tests: PLACEHOLDER_STRINGS.map((text) => [text, api.PLACEHOLDER_RE.test(text)]),
    }),
    exportsCredentialKeyRe: (api) => ({
        source: api.CREDENTIAL_KEY_RE.source,
        flags: api.CREDENTIAL_KEY_RE.flags,
        tests: CHECKED_KEYS.map((key) => [key, api.CREDENTIAL_KEY_RE.test(key)]),
    }),
    exportsIsSecretKeyName: (api) => CHECKED_KEYS.map((key) => [key, api.isSecretKeyName(key)]),
    exportsSkipKeys: (api) => [...api.STRUCTURAL_SKIP_KEYS],
    exportsBuildPlaceholder: (api) => {
        const lengths = [0, 1, 14, 15, 16, 17, 20, 40];
        const rules = ['aws', '@secretlint/secretlint-rule-aws', 'mobilerun-redaction/jwt', 'a:b', ''];
        const tails = ['wxyz', '[x]]', 'a b ', '\n\t:  ', '😀😀', 'a[]b'];
        return rules.flatMap((rule) => {
            return lengths.flatMap((length) => {
                return tails.map((tail) => {
                    const matched = `${'a'.repeat(length)}${tail}`;
                    return [rule, matched.length, api.buildPlaceholder(rule, matched)];
                });
            });
        });
    },
    exportsShorten: (api) => {
        const ids = [
            '@secretlint/secretlint-rule-aws',
            'mobilerun-redaction/x',
            '@secretlint/secretlint-rule-',
            'x',
            '',
        ];
        return ids.map((id) => [id, api.shortenRuleId(id), api.buildReadPlaceholder(id)]);
    },
    last4Text: async (api) => {
        const out: Json[] = [];
        for (const text of LONG_SECRETS) out.push(await asyncText(api, text, { last4: true }));
        for (const text of LONG_SECRETS) out.push(await asyncText(api, text, { last4: false }));
        for (const text of LONG_SECRETS) out.push(await asyncText(api, text));
        return out;
    },
    last4Json: async (api) => {
        const value = {
            password: 'S0mmer2026!xTr0ub4dor',
            token: 'short',
            nested: { secret: 'a'.repeat(16), list: ['b'.repeat(15), 'c'.repeat(17)] },
            pin: 1234,
            note: SECRET,
            type: 'x',
        };
        return [
            await asyncJson(api, value, { last4: true }),
            await asyncJson(api, value, { last4: true, skipKeys: new Set(['password']) }),
            await asyncJson(api, value, {}),
            await syncJson(api, value, { last4: true }),
        ];
    },
    last4Restore: async (api) => {
        const stored = {
            password: 'S0mmer2026!xTr0ub4dor',
            note: SECRET,
            list: [{ id: 'a', token: 'Zq9abcDEF123ghi_x' }],
        };
        const stats = { hits: [] as unknown[] };
        const redacted = await api.redactJsonValue(stored, stats, { last4: true });
        return [await capture(() => api.restoreRedacted(redacted, stored)), encode(redacted)];
    },
    detectOverride: async (api) => {
        const text = `hello ${SECRET} world`;
        const hit = (ruleId: string, a: number, b: number) => ({ ruleId, range: [a, b] });
        const detectors: Array<[string, (t: string) => Promise<unknown>]> = [
            ['empty', async () => []],
            ['one', async () => [hit('x', 0, 5)]],
            ['overlap', async () => [hit('x', 0, 8), hit('y', 4, 12), hit('z', 12, 14)]],
            ['unsorted', async () => [hit('b', 10, 12), hit('a', 0, 3)]],
            ['outOfRange', async () => [hit('x', 3, 999)]],
            ['negative', async () => [hit('x', -2, 3)]],
            ['reversed', async () => [hit('x', 9, 3)]],
            ['emptyRange', async () => [hit('x', 4, 4)]],
            ['longRuleId', async () => [hit('@secretlint/secretlint-rule-aws', 0, 20)]],
            [
                'throws',
                async () => {
                    throw new Error(`leak ${SECRET}`);
                },
            ],
            [
                'throwsString',
                async () => {
                    throw 'plain string';
                },
            ],
            [
                'throwsNull',
                async () => {
                    throw null;
                },
            ],
            [
                'throwsTypeError',
                async () => {
                    throw new TypeError('t');
                },
            ],
            ['returnsUndefined', async () => undefined],
            ['returnsNotArray', async () => ({})],
        ];
        const out: Json[] = [];
        for (const [name, detect] of detectors) {
            out.push([
                name,
                await asyncText(api, text, { detect }),
                await asyncText(api, text, { detect, last4: true }),
            ]);
        }
        return out;
    },
    detectOverrideJson: async (api) => {
        const detect = async (): Promise<unknown> => {
            throw new Error('boom');
        };
        return [
            await asyncJson(api, { a: `x ${SECRET}`, password: 'abc', list: [SECRET] }, { detect }),
            await asyncJson(
                api,
                { a: `x ${SECRET}` },
                { detect: async () => [{ ruleId: 'x', range: [0, 2] }] },
            ),
        ];
    },
    eventsDetectFailed: async (api) => {
        const failing = async (): Promise<never> => {
            throw new RangeError(`secret ${SECRET}`);
        };
        return [
            await events(api, `a ${SECRET}`, { detect: failing }),
            await events(api, `a ${SECRET}`, {
                detect: failing,
                onEvent: () => {
                    throw new Error('cb');
                },
            }),
            await events(api, `a ${SECRET}`, { detect: async () => [] }),
        ];
    },
    eventsThrowingCallback: async (api) => {
        const out: Json[] = [];
        const callbacks: Array<[string, (n: string, a: unknown) => unknown]> = [
            [
                'throws',
                () => {
                    throw new Error('cb');
                },
            ],
            ['rejects', () => Promise.reject(new Error('cb'))],
            ['async', async () => {}],
        ];
        for (const [name, onEvent] of callbacks) {
            const failing = async (): Promise<never> => {
                throw new Error('x');
            };
            out.push([name, await asyncText(api, `a ${SECRET}`, { detect: failing, onEvent })]);
        }
        await drain();
        return out;
    },
    eventsCapped: async (api) => {
        const filler = 'ab '.repeat(666_700);
        const text = `${filler} tail ${SECRET}`;
        return [await events(api, text, {}), await events(api, `${filler}${filler}`, { last4: true })];
    },
    asyncIgnoresLimits: async (api) => {
        const value = { a: SECRET, list: [SECRET, SECRET], deep: { deeper: { deepest: SECRET } } };
        return [
            await asyncJson(api, value, { maxChars: 5, maxDepth: 1, maxNodes: 2 }),
            await asyncText(api, SECRET, { maxChars: 5 }),
        ];
    },
    syncUnknownOptions: async (api) => {
        const value = { a: SECRET, list: [SECRET] };
        return [
            await syncJson(api, value, { last4: true, mode: undefined, detect: () => [] }),
            await capture(() => api.redactTextSync(SECRET, { last4: true, maxChars: 1000 })),
        ];
    },
    detectSecretsDirect: async (api) => {
        const out: Json[] = [];
        for (const text of [SECRET, '', 'short', `a ${SECRET}`, LONG_SECRETS.join('\n')]) {
            out.push(await capture(() => api.detectSecrets(text)));
        }
        return out;
    },
    nonJsonSync: async (api) => {
        const out: Record<string, Json> = {};
        for (const [name, make] of Object.entries(weirdValues())) out[name] = await syncJson(api, make());
        return out;
    },
    nonJsonSyncSmallLimits: async (api) => {
        const out: Record<string, Json> = {};
        for (const [name, make] of Object.entries(weirdValues())) {
            out[name] = await syncJson(api, make(), { maxDepth: 2, maxNodes: 4, maxChars: 40 });
        }
        return out;
    },
    nonJsonAsync: async (api) => {
        const out: Record<string, Json> = {};
        // The async walker has no cycle guard (it never returns on a cycle): cycles are sync-only probes.
        const skipped = new Set(['cycle', 'arrayCycle']);
        for (const [name, make] of Object.entries(weirdValues())) {
            if (!skipped.has(name)) out[name] = await asyncJson(api, make());
        }
        return out;
    },
    nonJsonText: async (api) => {
        const odd: unknown[] = [
            undefined,
            null,
            5,
            12n,
            {},
            [],
            Symbol.for('x'),
            new String('password=Zq9abcDEF123ghi_x'),
        ];
        const out: Json[] = [];
        for (const value of odd) {
            out.push(await capture(() => api.redactTextSync(value as string)));
            out.push(await capture(() => api.redactText(value as string)));
        }
        return out;
    },
};

export async function runBehaviors(api: Api): Promise<Record<string, unknown>> {
    const results: Record<string, unknown> = {};
    for (const [name, probe] of Object.entries(PROBES)) {
        results[name] = await capture(() => probe(api));
    }
    return results;
}
