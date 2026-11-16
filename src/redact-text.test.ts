/**
 * redact-text.test.ts — W3 core coverage for the secretlint-backed
 * detect+replace pipeline. Redaction is always on — no `enabled` opt to pass.
 */
import { describe, expect, mock, test } from 'bun:test';
import { detectSecrets, redactText } from './redact-text.js';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

describe('positive fixtures — one per rule family', () => {
    test('AWS: Access Key ID (needs enableIDScanRule — spike-verified default is OFF ' +
        'upstream, ON in our config)', async () => {
        const { text, hits } = await redactText('creds: AKIAQR7ZKT4MW2PLX9BD');
        expect(text).not.toContain('AKIAQR7ZKT4MW2PLX9BD');
        expect(hits.some((h) => h.ruleId.includes('aws'))).toBe(true);
    });

    test('AWS: Secret Access Key (40 chars, AWS_SECRET_ACCESS_KEY= context — fires ' +
        'regardless of enableIDScanRule)', async () => {
        const secret = 'wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY9xxx1';
        expect(secret).toHaveLength(40);
        const { text } = await redactText(`AWS_SECRET_ACCESS_KEY=${secret}`);
        expect(text).not.toContain(secret);
    });

    test('OpenAI: classic sk-...T3BlbkFJ... shape (realistic infix, not a generic sk- prefix)', async () => {
        const key = `sk-${'a'.repeat(20)}T3BlbkFJ${'b'.repeat(20)}`;
        const { text, hits } = await redactText(`key is ${key}`);
        expect(text).not.toContain(key);
        expect(hits.some((h) => h.ruleId.includes('openai'))).toBe(true);
    });

    test('GitHub token (upstream preset rule, unmodified)', async () => {
        const { text, hits } = await redactText(
            'my github token is ghp_16C7e42F292c6912E7710c838347Ae178B4a',
        );
        expect(text).not.toContain('ghp_16C7e42F292c6912E7710c838347Ae178B4a');
        expect(hits.some((h) => h.ruleId.includes('github'))).toBe(true);
    });

    test('JWT (custom rule — not in preset-recommend)', async () => {
        const jwt =
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.' +
                'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c';
        const { text, hits } = await redactText(`bearer ${jwt}`);
        expect(text).not.toContain(jwt);
        expect(hits.some((h) => h.ruleId === 'mobilerun-redaction/jwt')).toBe(true);
    });

    test('generic keyword+value: password:', async () => {
        const { text } = await redactText('login: admin password: S0mmer2026!xTr0ub4dor');
        expect(text).toContain('login: admin');
        expect(text).not.toContain('S0mmer2026!xTr0ub4dor');
    });

    test('generic keyword+value: snake_case label (session_token) — identifier-aware match', async () => {
        const { text } = await redactText('session_token: aB3xK9mQ2pL7wZ4v');
        expect(text).not.toContain('aB3xK9mQ2pL7wZ4v');
    });

    test('generic keyword+value: camelCase label (clientSecret) — identifier-aware match', async () => {
        const { text } = await redactText('clientSecret=Zx9mK2pL7wQ4vB3xA1c');
        expect(text).not.toContain('Zx9mK2pL7wQ4vB3xA1c');
    });

    test('database connection string (upstream preset rule, unmodified)', async () => {
        const { text } = await redactText('postgres://admin:hunter2secret@db.example.com:5432/app');
        expect(text).not.toContain('hunter2secret');
    });

    test('Google (GCP) API key: AIza + 35-char body (custom rule — gcp preset only ' +
        'parses .p12/.json files)', async () => {
        const key = 'AIza3EiODjfjghFw2GS6-hZByGzeM386y6zvl5f';
        expect(key).toHaveLength(39);
        const { text, hits } = await redactText(`GOOGLE_API_KEY=${key}`);
        expect(text).not.toContain(key);
        expect(hits.some((h) => h.ruleId === 'mobilerun-redaction/gcp-api-key')).toBe(true);
    });

    test('xAI (x.ai / Grok) API key: xai- + 80-char body (custom rule — no upstream ' +
        'coverage at all)', async () => {
        const key = 'xai-Y7a1R_QjyDLgpFegN9uQL6yMqjhAl9bXEqgWZtj2dXWHMsj5yskfHYLRe61tKKO_PW8NctSUR7m88X6R';
        expect(key).toHaveLength(84);
        const { text, hits } = await redactText(`XAI_API_KEY=${key}`);
        expect(text).not.toContain(key);
        expect(hits.some((h) => h.ruleId === 'mobilerun-redaction/xai-api-key')).toBe(true);
    });
});

describe('negative corpus — must NOT be flagged', () => {
    const negatives: [string, string][] = [
        ['bare UUID (no credential-keyword label)', 'device 3fa85f64-5717-4562-b3fc-2c963f66afa6 went ' +
            'offline'],
        ['bare SHA-1 hash', 'commit a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 fixed it'],
        ['bare base64 data URI', 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB'],
        ['plain URL', 'see https://example.com/path?query=abcdefgh123 for docs'],
        ['token: undefined', 'default config has token: undefined and that is fine'],
        ['doc placeholder (snake_case)', 'set api_key: your_api_key_here in the .env file'],
        ['doc placeholder (SCREAMING_SNAKE)', 'export TOKEN=REPLACE_ME_TOKEN'],
        ['doc placeholder (angle brackets)', 'Authorization: <your-token-here>'],
        ['trivial value: changeme', 'password: changeme'],
        ['trivial value: xxxxxxxx mask', 'api_key: xxxxxxxxxxxxxxxx'],
        ['trivial value: asterisk mask', 'secret: ****************'],
        ['short design token (below the 8-char floor)', 'spacing_token: 16px, color_token: #fff'],
        // Gap 1/2 false-positive guards: same-shape-but-wrong-length strings
        // must not trip the new fixed-length custom rules.
        [
            'AIza decoy: 34-char body (one short of the real 35) — not a valid Google key shape',
            'legacyId=AIzaS_f0sYnC4Rce_xcEmtOikZcYypDAJ7fS00',
        ],
        [
            'AIza decoy: 39-char random string that does NOT start with the literal AIza prefix',
            'reference=Bxyz3EiODjfjghFw2GS6hZByGzeM386y6zvl5',
        ],
        [
            'xai- decoy: bare "xai-" prefix used as an ordinary identifier fragment, not a key',
            'the xai-labs team renamed the xai-eval-harness repo',
        ],
        [
            'xai- decoy: 79-char body (one short of the real 80) — not a valid xAI key shape',
            'legacyRef=xai-ggCKZlvpearv6UguL2RM2ZLr0URcIqRjiVLGbVOIhBNHOYWiqldtDgVoe5q6B06GuCP9V0WBedjuS7c',
        ],
    ];
    for (const [label, text] of negatives) {
        test(label, async () => {
            const { text: out, hits } = await redactText(text);
            expect(out).toBe(text);
            expect(hits).toEqual([]);
        });
    }
});

describe('AIza boundary bug (Fix 1 — trailing \\b false-negative)', () => {
    test('AIza key whose LAST body char is "-" is redacted in ordinary prose (no ' +
        'credential-keyword label)', async () => {
        // Body chars: 34 alnum/_ chars + trailing '-' = 35, then whitespace
        // follows — a non-word ('-') to non-word (space) transition, which
        // the old trailing \b failed to match, letting the whole key escape.
        const key = 'AIzaE3ZVSHDBs43BRT3PrSvZ0KshZJRhDBmCji-';
        expect(key).toHaveLength(39);
        expect(key.endsWith('-')).toBe(true);
        const { text, hits } = await redactText(`the deploy log mentions ${key} in passing`);
        expect(text).not.toContain(key);
        expect(hits.some((h) => h.ruleId === 'mobilerun-redaction/gcp-api-key')).toBe(true);
    });

    test('AIza-shaped decoy with a 36-char body (one over the real 35) is NOT flagged', async () => {
        const decoy = 'AIzaX5wFmAbkO85TbATCmZwkKljQY9LVKxmYSf7e';
        expect(decoy).toHaveLength(40);
        const { text, hits } = await redactText(`ref=${decoy} end`);
        expect(text).toBe(`ref=${decoy} end`);
        expect(hits).toEqual([]);
    });
});

describe('bypass test — own preset excludes secretlint-rule-filter-comments', () => {
    test('a "// secretlint-disable" comment does NOT suppress detection', async () => {
        const text = '// secretlint-disable\npassword: S0mmer2026!xTr0ub4dor';
        const { text: out } = await redactText(text);
        expect(out).not.toContain('S0mmer2026!xTr0ub4dor');
    });
});

describe('idempotence + overlap', () => {
    test('re-scanning already-redacted text produces no further changes', async () => {
        const once = await redactText('password: S0mmer2026!xTr0ub4dor');
        expect(once.text).not.toContain('S0mmer2026!xTr0ub4dor');
        const twice = await redactText(once.text);
        expect(twice.text).toBe(once.text);
        expect(twice.hits).toEqual([]);
    });

    test('overlapping hits from two different rules on the same span collapse to ONE ' +
        'placeholder, not a corrupted double-splice', async () => {
        // The AWS Access Key ID pattern AND the generic keyword rule (label
        // "AWS_SECRET_ACCESS_KEY" contains "secret") both fire on
        // overlapping/adjacent spans of this fixture.
        const secret = 'wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY9xxx1';
        const { text } = await redactText(`AWS_SECRET_ACCESS_KEY=${secret}`);
        // No leftover secret fragment, no garbled/duplicated placeholder text.
        expect(text).not.toContain(secret);
        expect(text.match(/\[REDACTED:/g)?.length).toBeGreaterThanOrEqual(1);
    });

    test('a later, farther-reaching overlapping hit is MERGED (unioned), not dropped ' +
        '— no secret material survives past the first hit\'s end', async () => {
        // Exact repro of the P1 finding: the AWS rule fires on [0,40) and the
        // generic-keyword rule (triggered by "SECRET" in the label) fires on
        // [22,62) of this fixture — a genuine overlap, not a nested/duplicate
        // match. The old dedupe kept only the first-sorted hit ([0,40)) and
        // silently dropped the second, leaving chars 40-62 — real secret
        // material — in plaintext after redaction.
        const secret = 'wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY9xxx1';
        const text = `AWS_SECRET_ACCESS_KEY=${secret}`;
        const { text: out } = await redactText(text);
        // Nothing of the secret survives anywhere in the output, including
        // the tail past the old (buggy) [0,40) cutoff.
        expect(out).not.toContain(secret);
        expect(out).not.toContain(secret.slice(18));
        // The two ranges merge into ONE placeholder spanning the full union
        // — a single marker built from the merged (62-char) match, carrying
        // the ruleId of the earliest-starting hit (aws).
        expect(out).toBe(`[REDACTED:aws:${secret.slice(-4)}]`);
    });

    test('two independent, non-overlapping hits in one string both get placeholders', async () => {
        const { text } = await redactText(
            'first: ghp_16C7e42F292c6912E7710c838347Ae178B4a then password: S0mmer2026!xTr0ub4dor',
        );
        expect(text).not.toContain('ghp_16C7e42F292c6912E7710c838347Ae178B4a');
        expect(text).not.toContain('S0mmer2026!xTr0ub4dor');
        expect(text.match(/\[REDACTED:/g)?.length).toBe(2);
    });
});

describe('placeholder shape', () => {
    test('match >=16 chars gets ruleId:last4', async () => {
        const { text } = await redactText('ghp_16C7e42F292c6912E7710c838347Ae178B4a');
        expect(text).toMatch(/^\[REDACTED:github:[A-Za-z0-9]{4}\]$/);
    });

    test('short match (<16 chars) omits last4 — otherwise it would leak ~half the material', async () => {
        // A 12-char value: last4 would be 1/3 of the secret.
        const { text } = await redactText('pwd=Ab1!Ab1!'); // upper+lower+digit+special
        expect(text).toBe('pwd=[REDACTED:generic-keyword]');
    });
});

describe('length guards', () => {
    test('below the 8-char prefilter: never even invoked against the engine', async () => {
        const { text, hits } = await redactText('short');
        expect(text).toBe('short');
        expect(hits).toEqual([]);
    });

    test('a <100k string is scanned in a single window — identical to pre-chunking behavior', async () => {
        // Sanity-check the "no chunking below MAX_SCAN_LEN" contract: a
        // secret near the end of a ~50k string (well under one window) is
        // still found exactly once, no duplicate/garbled placeholder from
        // spurious windowing.
        const secret = 'Qx7mP2vL9wZaB4nR8kFjT3hY6cWe1sNq';
        const text = 'y'.repeat(50_000) + ` password: ${secret}`;
        const { text: out, hits } = await redactText(text);
        expect(out).not.toContain(secret);
        expect(hits).toHaveLength(1);
    });

    test('a huge (150k) blob with no secret does not hang and does not log ' +
        'redaction.scan.capped', async () => {
        const warnSpy = mock((_name: string, _attrs: Record<string, unknown>) => {});
        const huge = 'x'.repeat(150_000);
        const t0 = performance.now();
        const { text } = await redactText(huge, { onEvent: warnSpy });
        const elapsedMs = performance.now() - t0;
        const cappedWarns = warnSpy.mock.calls.filter(([event]) => event === 'redaction.scan.capped');
        expect(text).toBe(huge);
        expect(elapsedMs).toBeLessThan(5000);
        // 150k is well under MAX_TOTAL_SCAN_LEN (2M) — chunked-but-uncapped.
        expect(cappedWarns).toHaveLength(0);
    });

    test('a secret placed well beyond the OLD 100k head-only cutoff (offset 120_000) ' +
        'IS now caught — this was the leak this wave fixes', async () => {
        const secret = 'Ab9cD3eF7gH1iJ5kL2mNoPqRsTuVwXyZ';
        const text = 'z'.repeat(120_000) + ` clientSecret=${secret}`;
        const { text: out, hits } = await redactText(text);
        expect(out).not.toContain(secret);
        expect(hits.length).toBeGreaterThan(0);
    });

    test('a secret straddling the 100k window boundary is caught by the overlap, not ' +
        'split/missed', async () => {
        const secret = 'Vr8tGq3mXpL6bWc9zNe2sYh5fKd1uAoI';
        // Position the secret so it starts before offset 100_000 and ends
        // after it — a naive non-overlapping chunk split would cut the
        // match in half in BOTH windows and miss it entirely.
        const prefix = 'w'.repeat(99_970);
        const text = `${prefix} apiKey=${secret}`;
        const boundaryIndex = text.indexOf('apiKey=') + 'apiKey='.length;
        expect(boundaryIndex).toBeLessThan(100_000);
        expect(boundaryIndex + secret.length).toBeGreaterThan(100_000);
        const { text: out, hits } = await redactText(text);
        expect(out).not.toContain(secret);
        expect(hits.length).toBeGreaterThan(0);
    });

    test('a PEM-sized secret (>512, the OLD overlap) straddling a 100k window ' +
        'boundary IS redacted, and collapses to exactly ONE placeholder', async () => {
        // Freshly generated for this test (openssl genrsa 2048) — not a
        // canonical docs example key. ~1.7k chars, comfortably bigger than
        // the OLD SCAN_OVERLAP=512 (which would have split/missed a match
        // straddling the boundary) and well inside the NEW SCAN_OVERLAP.
        const pem = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDfU36d/BY7T9t2
gbzxK15q2zNdjeCxdWZKJXB8o6Nu1Lq2O4bCSotp/nHKcke2mTMN+ssRuZ9NKGJZ
xMuL7OXn9kpYTA0SF3bZNZnuCTcHRKIldWRGcV/rPf2TrFO+QWZ/BHHFc9Ey5rAw
ANwt8noivSeQPpNALXM/+vGybpLL0juu1Tp5iMlIUEtPEQ4QTs2VUdNLGMQQ2mb2
Bfeih+MmGLOovez4hubBciiiZKE0jp3fa9OuD7odgIGNhC5YgNIQucGElcqh3L+D
fPZZq4lGxEY2HB+XG15vqgyg1ZYUQ5/mtqANmQ8n48JYvekjHP0aIE3/dgzWve7v
8w61X5WLAgMBAAECggEADd2cPejZ5ILXyGrTtVGRAidr8AIQElSMrkvWyRZL3mS8
1vWpL0T7lPAkVoJz62VloxeQJiCVQHAicxph3OUvfRBwmzzVjusACQpn7TyLOxtK
yfKY8Dq3zt5BcTrA1E4xM++ttKm1MmjaRZC4Gu40IRYHb9BCyjhIMI+/E+oDmT3t
mfyYe1YHz1t5YZEZ5QeQlLRpHnHsgFe1Q2ANwWwkqbXnWdCkwTfzUN/diikW4d8T
JFdQZsqS3thncBTFyr58PiCbw8Tj6Jr8ukA/A3pywRCJvohGzWCH+M3wagOV3l0c
X6gknCXKzk3WZKMaQF7deTXzm8H43F858ERUvc+YyQKBgQD4m+xy1DCZ9PH0aIZ1
b/hZ0dzeIq9mT3CGMwSLY3FSeAVnnflzTDeF5UdCUDNeUFEKvBGGmsrD8HANRqmr
1XFk6fJreuT+dfM5A34p1ywc8gzRH4Fa6NvfBgJ3oxfN83U9Hr5P/u6RVuNKrK/3
mHntwU8w5e6V1Qu1LHHGP1913QKBgQDl9ybIyFsR229n4owj2S8HeGZveSDkUDeC
EeF0NOb/CqZzYacvILiJw/81+C9O6SaMEMOi8n4L6wypWKUqhlB7JJYEih8LXqDG
aAbFu3gsYJbRELBz64GJROsDSJwhN/XJePq/5sC0Cvf+N4FWDKyh/xLe9VERUJX1
F7sZ5SZGhwKBgAeEv6vhWu7tB3w6xQY8MqiUvjdBmUhg0qhcVqDYiw7Rbmhp0Kd6
AJveCT+qKUOK7kiC04zclZFDbkAYiP0XYWyJ3rj9aHuBma95uZEOXtkpQNX6O/FB
5ZRjHCP+HLQvzrXgfiTxMsnWdN1HR7MXO2jDVd/GtGZ3oPkDtRUnyX1JAoGBAKUZ
Ypvl1BQm8X2o1Snrg+seEpTXZrjjqmZUhgNS88CJGeVeZ5PbLwGhWDmb/ALwOn92
ja4P4FSYJNfzz2iPU3qFUrrhmtYj0tN+3dXZ+LYLhluEWtpuauptMziBSa5Dqc9C
buuVNCZOdarqmI15vfrz0M2HW/NNYsu6hNZbgLZDAoGBANhLbENwHd3HZssN7ZEn
0rBdQ4LsRakEuEtGcDx3jwtCsLjAJDb8lyR6GT+C5zEXt/iMF6ePZR2MFSnitiDm
bUYm3BPmcU25IA5I3TuFELVEQm3dwFnr52EgbIAl8ov82Xs5FsNeVJTkvSsJwkA0
123eA1TsWT4CQ8db11u0Od5Z
-----END PRIVATE KEY-----`;
        expect(pem.length).toBeGreaterThan(512);
        // Position so the PEM block itself straddles the 100k boundary.
        const prefix = 'w'.repeat(99_500);
        const text = `${prefix}\n${pem}\ntrailer text`;
        const pemStart = text.indexOf('-----BEGIN PRIVATE KEY-----');
        expect(pemStart).toBeLessThan(100_000);
        expect(pemStart + pem.length).toBeGreaterThan(100_000);
        const { text: out, hits } = await redactText(text);
        expect(out).not.toContain('MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDfU36d');
        expect(out).not.toContain('123eA1TsWT4CQ8db11u0Od5Z');
        // Reported once by whichever window(s) it fell in, but dedupeRanges
        // collapses any overlapping duplicate reports into a single hit.
        const pemHits = hits.filter((h) => out.includes('[REDACTED:') && h.range[1] - h.range[0] > 500);
        expect(pemHits.length).toBe(1);
        expect(out.match(/\[REDACTED:/g)?.length).toBe(1);
    });

    test('a string beyond the 2M absolute cap: scans up to the cap (catching a ' +
        'secret inside it), logs redaction.scan.capped, and does not scan past it', async () => {
        const warnSpy = mock((_name: string, _attrs: Record<string, unknown>) => {});
        const insideSecret = 'Lk4pQw8eRt2yUi6oAs1dFg5hJz9xCvBn';
        const beyondSecret = 'Mo3nBv7cXz1lKj5hGf9dSa2wQe6rTy8u';
        // One secret comfortably inside the 2M cap, one placed past it.
        const text =
            `password: ${insideSecret} ` +
            'q'.repeat(2_000_000) +
            ` password: ${beyondSecret}`;
        expect(text.length).toBeGreaterThan(2_000_000);
        const { text: out, hits } = await redactText(text, { onEvent: warnSpy });
        const cappedWarns = warnSpy.mock.calls.filter(([event]) => event === 'redaction.scan.capped');
        expect(out).not.toContain(insideSecret);
        expect(out).toContain(beyondSecret); // past the cap — documented trade-off, not a bug
        expect(hits.length).toBeGreaterThan(0);
        expect(cappedWarns).toEqual([
            ['redaction.scan.capped', { originalLength: text.length, scannedLength: 2_000_000 }],
        ]);
    }, 20_000);
});

describe('fail-open: detector exceptions never throw, never leak the exception message into logs', () => {
    test('a throwing detector: redactText returns the ORIGINAL text unredacted ' +
        'rather than losing data', async () => {
        const throwingDetect = async (): Promise<never> => {
            throw new Error('regex engine choked on: sk-supersecretvalue123456');
        };
        const { text, hits } = await redactText('some message text', { detect: throwingDetect });
        expect(text).toBe('some message text');
        expect(hits).toEqual([]);
    });

    test('the logged warning contains NO trace of the exception message (which could ' +
        'itself echo the secret)', async () => {
        const LEAKED_SECRET_MARKER = 'sk-supersecretvalue123456';
        const throwingDetect = async (): Promise<never> => {
            throw new Error(`regex engine choked on: ${LEAKED_SECRET_MARKER}`);
        };
        const warnSpy = mock((_name: string, _attrs: Record<string, unknown>) => {});
        await redactText('some message text', { detect: throwingDetect, onEvent: warnSpy });
        const loggedAnywhere = warnSpy.mock.calls.some(
            (args) => JSON.stringify(args).includes(LEAKED_SECRET_MARKER),
        );
        expect(loggedAnywhere).toBe(false);
        expect(warnSpy.mock.calls).toEqual([
            ['redaction.detect.failed', { errorName: 'Error' }],
        ]);
    });

    test('a non-Error throw (string) is also handled without crashing', async () => {
        const throwingDetect = async (): Promise<never> => {
            // eslint-disable-next-line @typescript-eslint/only-throw-error
            throw 'a plain string throw, not an Error instance';
        };
        const { text, hits } = await redactText('some message text', { detect: throwingDetect });
        expect(text).toBe('some message text');
        expect(hits).toEqual([]);
    });

    test('an event callback failure cannot break detector fail-open', async () => {
        const result = await redactText('some message text', {
            detect: async () => {
                throw new Error('detector failed');
            },
            onEvent: () => {
                throw new Error('telemetry failed');
            },
        });
        expect(result).toEqual({ text: 'some message text', hits: [] });
    });

    test('an async event callback rejection cannot escape detector fail-open', () => {
        const result = spawnSync(process.execPath, ['--eval', `
            import { strict as assert } from 'node:assert';
            const { redactText } = await import('./src/index.ts');
            let unhandledRejections = 0;
            process.on('unhandledRejection', () => {
                unhandledRejections++;
            });
            const events = [];
            const result = await redactText('some message text', {
                detect: async () => {
                    throw new Error('detector failed');
                },
                onEvent: async (name, attrs) => {
                    events.push([name, attrs]);
                    throw new Error('async telemetry failed');
                },
            });
            await new Promise((resolve) => setImmediate(resolve));
            assert.deepEqual(result, { text: 'some message text', hits: [] });
            assert.deepEqual(events, [['redaction.detect.failed', { errorName: 'Error' }]]);
            assert.equal(unhandledRejections, 0);
        `], {
            cwd: fileURLToPath(new URL('..', import.meta.url)),
            encoding: 'utf8',
            timeout: 10_000,
        });
        expect(result.error).toBeUndefined();
        expect(result.status, result.stderr).toBe(0);
    }, 20_000);
});

describe('detectSecrets (the unconditional primitive, used directly by redactText)', () => {
    test('returns [] for text below the min-length floor, without invoking the engine', async () => {
        expect(await detectSecrets('tiny')).toEqual([]);
    });

    test('returns hits with {ruleId, range} shape, never the matched text itself', async () => {
        const hits = await detectSecrets('ghp_16C7e42F292c6912E7710c838347Ae178B4a');
        expect(hits.length).toBeGreaterThan(0);
        for (const hit of hits) {
            expect(typeof hit.ruleId).toBe('string');
            expect(hit.range).toHaveLength(2);
        }
    });
});
