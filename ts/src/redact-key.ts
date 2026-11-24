/**
 * redact-key.ts — the object-key scan shared by the sync, the async and the strict
 * walkers: a key that itself holds a secret is replaced through the sync rules (in the full tier through the
 * full rules too).
 */
import { appendHits, applyHits, type Hit } from './hits.js';
import { ALGORITHMS_SPEC } from './spec.js';
import { detectSyncHits } from './sync-rules.js';

const MAX_KEY_CHARS = ALGORITHMS_SPEC.sync.maxKeyChars;

export type KeyDetector = (key: string) => Hit[];

/** True when a key is at least `floor` (`scanFloor`) and at most `maxKeyChars` long (longer ones stay). */
export function isScannableKey(key: string, floor: number): boolean {
    return key.length >= floor && key.length <= MAX_KEY_CHARS;
}

/** The key as written, or its placeholder when the key text itself holds a secret. `detect` is the standard
 *  rules (default) or, in the full tier, the full-tier rules too (SPEC 9.4); it is the one that knows the
 *  shortest key it scans. */
export function redactKey(key: string, hits: Hit[], detect: KeyDetector = detectSyncHits): string {
    if (isOverlongKey(key)) return key;
    const found = detect(key);
    if (found.length === 0) return key;
    appendHits(hits, found);
    return applyHits(key, found);
}

/** True when `redactKey` leaves a key unscanned because it is too long (the strict walkers refuse that). */
export function isOverlongKey(key: string): boolean {
    return key.length > MAX_KEY_CHARS;
}
