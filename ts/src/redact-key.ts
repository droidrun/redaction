/**
 * redact-key.ts — the object-key scan shared by the sync, the async and the strict
 * walkers: a key that itself holds a secret is replaced through the sync rules.
 */
import { appendHits, applyHits, type Hit } from './hits.js';
import { ALGORITHMS_SPEC } from './spec.js';
import { detectSyncHits } from './sync-rules.js';

const MIN_SCAN_LEN = ALGORITHMS_SPEC.text.minScanLength;
const MAX_KEY_CHARS = ALGORITHMS_SPEC.sync.maxKeyChars;

/** The key as written, or its placeholder when the key text itself holds a secret. */
export function redactKey(key: string, hits: Hit[]): string {
    if (key.length < MIN_SCAN_LEN || key.length > MAX_KEY_CHARS) return key;
    const found = detectSyncHits(key);
    if (found.length === 0) return key;
    appendHits(hits, found);
    return applyHits(key, found);
}

/** True when `redactKey` leaves a key unscanned because it is too long (the strict walkers refuse that). */
export function isOverlongKey(key: string): boolean {
    return key.length > MAX_KEY_CHARS;
}
