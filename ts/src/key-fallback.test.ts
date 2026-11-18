/**
 * key-fallback.test.ts — a key scan that fails never passes the key and never fails the call: compat falls back to
 * the standard rules, like a leaf (`redactText`).
 */
import { afterEach, expect, spyOn, test } from 'bun:test';
import * as fullRules from './full-rules.js';
import { redactJsonValue } from './redact-value.js';

const GH = `ghp_${'a'.repeat(36)}`;
const NPM = `npm_${'A'.repeat(36)}`;

afterEach(() => {
    spyOn(fullRules, 'detectFullTierKeyHits').mockRestore();
});

test('a failing full-tier key detector falls back to the standard rules for that key', async () => {
    spyOn(fullRules, 'detectFullTierKeyHits').mockImplementation(() => {
        throw new Error('detector down');
    });
    const out = await redactJsonValue({ [GH]: 1, [NPM]: 2, plain_name: 3 }, { hits: [] });
    // The standard rules still replace the GitHub key; the npm key is a full-tier format and stays as the
    // standard rules leave it. Nothing throws.
    expect(out).toEqual({ '[REDACTED:github]': 1, [NPM]: 2, plain_name: 3 });
});
