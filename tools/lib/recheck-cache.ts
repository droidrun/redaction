/**
 * recheck-cache — remembers the gate decision (safe, warning with its attack, or problem) per pattern, so an
 * unchanged pattern is not analysed again. The key is a sha256 over everything the decision depends on
 * (see `gateKey` in recheck-gate.ts); a changed pattern, a new recheck version or a changed gate setting
 * therefore misses. The file lives in a gitignored directory; CI restores and saves it with actions/cache.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Gate } from './recheck-gate.ts';

/** Raised when the meaning of a stored decision changes: an old file is then ignored. */
export const CACHE_FORMAT = 1;

export type GateCache = {
    get: (key: string) => Gate | undefined;
    set: (key: string, gate: Gate) => void;
};

export function hashParts(parts: string[]): string {
    const hash = createHash('sha256');
    for (const part of parts) {
        hash.update(part);
        hash.update('\0');
    }
    return hash.digest('hex');
}

type CacheFile = { format: number; entries: Record<string, Gate> };

function readEntries(path: string): Map<string, Gate> {
    try {
        const file = JSON.parse(readFileSync(path, 'utf8')) as CacheFile;
        return file.format === CACHE_FORMAT ? new Map(Object.entries(file.entries)) : new Map();
    } catch {
        return new Map();
    }
}

export class FileGateCache implements GateCache {
    private readonly entries: Map<string, Gate>;
    private readonly used = new Set<string>();

    constructor(private readonly path: string) {
        this.entries = readEntries(path);
    }

    get(key: string): Gate | undefined {
        const gate = this.entries.get(key);
        if (gate !== undefined) this.used.add(key);
        return gate;
    }

    set(key: string, gate: Gate): void {
        this.entries.set(key, gate);
        this.used.add(key);
    }

    /** `pruneUnused` drops every entry this run did not touch (a full run knows all current patterns). */
    save(pruneUnused: boolean): void {
        const kept = [...this.entries].filter(([key]) => !pruneUnused || this.used.has(key));
        const file: CacheFile = { format: CACHE_FORMAT, entries: Object.fromEntries(kept) };
        mkdirSync(dirname(this.path), { recursive: true });
        writeFileSync(this.path, JSON.stringify(file));
    }
}
