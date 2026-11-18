/**
 * key-detectors — the key scans a placeholder key can have come from: the standard rules, and the full-tier rules
 * once the full tier is loaded (the main entry loads it; `./sync` does not). `restoreRedacted` (SPEC 8, restore of
 * keys) tries each of them, so a key redacted by either entry maps back to its stored key.
 */
import type { KeyDetector } from './redact-key.js';
import { detectSyncHits } from './sync-rules.js';

const DETECTORS: KeyDetector[] = [detectSyncHits];

/** Called by the full tier when it loads. */
export function registerFullKeyDetector(detect: KeyDetector): void {
    if (!DETECTORS.includes(detect)) DETECTORS.push(detect);
}

export function loadedKeyDetectors(): readonly KeyDetector[] {
    return DETECTORS;
}
