/**
 * recheck-cache.test.ts — an unchanged pattern is not analysed again, a changed one is; the stored decision keeps
 * its warning or problem; the file survives a round trip and drops what a full run did not touch.
 */
import { expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileGateCache, type GateCache } from './recheck-cache.ts';
import { cachedRecheckGate, type Gate } from './recheck-gate.ts';

const ATTACK = { pumps: [{ prefix: 'a', pump: 'b', bias: 0 }], suffix: '!', base: 1, string: 'ab!' };

function memory(): GateCache {
    const entries = new Map<string, Gate>();
    return { get: (key) => entries.get(key), set: (key, gate) => void entries.set(key, gate) };
}

function counting(status: string): { calls: string[]; deps: Parameters<typeof cachedRecheckGate>[3] } {
    const calls: string[] = [];
    const deps = {
        check: async (source: string) => {
            calls.push(source);
            return { status, attack: ATTACK, complexity: { summary: 'polynomial' } };
        },
        confirm: () => undefined,
    };
    return { calls, deps };
}

test('an unchanged pattern hits the cache and is not analysed again', async () => {
    const cache = memory();
    const { calls, deps } = counting('safe');
    await cachedRecheckGate('p1', 'x+y', cache, deps);
    await cachedRecheckGate('p1', 'x+y', cache, deps);
    expect(calls).toEqual(['x+y']);
});

test('a changed pattern misses the cache', async () => {
    const cache = memory();
    const { calls, deps } = counting('safe');
    await cachedRecheckGate('p1', 'x+y', cache, deps);
    await cachedRecheckGate('p1', 'x+z', cache, deps);
    expect(calls).toEqual(['x+y', 'x+z']);
});

test('without a cache every call analyses', async () => {
    const { calls, deps } = counting('safe');
    await cachedRecheckGate('p1', 'x+y', undefined, deps);
    await cachedRecheckGate('p1', 'x+y', undefined, deps);
    expect(calls).toEqual(['x+y', 'x+y']);
});

test('a stored warning comes back with the label of the pattern asked for and its attack', async () => {
    const cache = memory();
    const { deps } = counting('vulnerable');
    const first = await cachedRecheckGate('old label', 'x+y', cache, deps);
    const second = await cachedRecheckGate('new label', 'x+y', cache, deps);
    expect(first.warning?.startsWith('old label: recheck says vulnerable')).toBe(true);
    expect(second.warning).toBe(first.warning?.replace('old label', 'new label'));
    expect(second.warning).toContain('attack "ab!"');
});

test('a stored problem still fails', async () => {
    const cache = memory();
    const { deps } = counting('unknown');
    await cachedRecheckGate('p1', 'x+y', cache, deps);
    const again = await cachedRecheckGate('p1', 'x+y', cache, deps);
    expect(again.problem).toBe('p1: recheck says unknown (no attack string to confirm)');
});

test('the file keeps entries across instances; a pruning save drops the untouched ones', () => {
    const dir = mkdtempSync(join(tmpdir(), 'recheck-cache-'));
    try {
        const path = join(dir, 'nested', 'gate.json');
        const writer = new FileGateCache(path);
        writer.set('a', {});
        writer.set('b', { warning: ': w' });
        writer.save(false);
        const reader = new FileGateCache(path);
        expect(reader.get('b')).toEqual({ warning: ': w' });
        reader.save(true);
        const pruned = new FileGateCache(path);
        expect(pruned.get('a')).toBeUndefined();
        expect(pruned.get('b')).toEqual({ warning: ': w' });
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
