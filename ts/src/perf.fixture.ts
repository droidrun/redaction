/**
 * perf-fixture.ts — a deterministic list of realistic action params for the
 * perf budget test: HTTP requests with headers and JSON bodies, scripts with
 * shell lines, SMS and UI steps. About a third carry a (fake) secret.
 */
import { setOwnKey } from './own-key.js';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH'] as const;

function fakeJwt(n: number): string {
    return `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLSR7${String(n).padStart(6, '0')}In0.` +
        `SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c${n % 10}`;
}

function httpParams(n: number): Record<string, unknown> {
    const secret = n % 3 === 0;
    const query = secret ? `&token=Zq9fake${n}_x` : '';
    const headers: Record<string, unknown> = {
        'Content-Type': 'application/json',
        Accept: 'application/json',
    };
    if (secret) setOwnKey(headers, 'Authorization', `Bearer ${fakeJwt(n)}`);
    if (n % 6 === 0) setOwnKey(headers, 'X-Api-Key', `k_live_${n}Zq9fakeMARKER`);
    return {
        method: METHODS[n % METHODS.length],
        url: `https://api.example.test/v1/items/${n}?page=${n % 7}&sort=asc${query}`,
        headers,
        body: {
            name: `item ${n}`,
            tags: ['a', 'b', 'c'],
            owner: { email: `user${n}@example.test`, active: true },
        },
        timeoutMs: 30_000,
    };
}

function scriptParams(n: number): Record<string, unknown> {
    const secret = n % 4 === 0;
    const bearer = secret ? fakeJwt(n) : 'placeholder-value';
    const code = [
        'set -euo pipefail',
        `curl -sS -H "Authorization: Bearer ${bearer}" https://api.example.test/v1/run/${n}`,
        `echo "done step ${n}" | tee /tmp/out-${n}.log`,
        secret ? `export DB_PASSWORD=Zq9fake${n}_xyz` : 'export REGION=eu-west-1',
    ].join('\n');
    return { language: 'bash', code, env: { REGION: 'eu-west-1', RETRIES: '3' } };
}

function deviceParams(n: number): Record<string, unknown> {
    return n % 2 === 0
        ? { action: 'tap', x: n % 1080, y: n % 1920, description: `Tap the sign in button on screen ${n}` }
        : { action: 'type', text: `hello world ${n}`, field: 'search', submit: true };
}

/** `count` action rows shaped like `GET /actions`: id, type, name and `params`. */
export function buildActions(count: number): Array<Record<string, unknown>> {
    const builders = [httpParams, scriptParams, deviceParams] as const;
    return Array.from({ length: count }, (_, n) => ({
        id: `3fa85f64-5717-4562-b3fc-${String(n).padStart(12, '0')}`,
        type: ['http.request', 'script.run', 'device.act'][n % 3],
        name: `Action ${n}`,
        description: `Step ${n} of the nightly routine, runs after the previous step finishes.`,
        params: builders[n % 3]!(n),
        createdAt: '2026-11-17T10:00:00.000Z',
    }));
}
