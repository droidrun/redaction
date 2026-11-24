/**
 * key-detectors — the key scans a placeholder key can have come from: the standard rules in each mode, with
 * and without `pii`, and the full-tier rules too once the full tier is loaded (the main entry loads it;
 * `./sync` does not). `restoreRedacted` (SPEC 8, restore of keys) tries each of them, so a key redacted by
 * any entry, mode or option maps back to its stored key. More than one stored key behind a placeholder key
 * stays a conflict.
 */
import type { KeyDetector } from './redact-key.js';
import { detectSyncHits, type DetectOpts } from './sync-rules.js';

const KEY_SCANS: readonly DetectOpts[] = [
    {},
    { pii: true },
    { mode: 'strict' },
    { mode: 'strict', pii: true },
];

const DETECTORS: KeyDetector[] = KEY_SCANS.map((opts) => (key) => detectSyncHits(key, opts));

let hasFullTier = false;

/** Called by the full tier when it loads: `make` gives its key scan for one set of options. */
export function registerFullKeyDetectors(make: (opts: DetectOpts) => KeyDetector): void {
    if (hasFullTier) return;
    hasFullTier = true;
    for (const opts of KEY_SCANS) DETECTORS.push(make(opts));
}

export function loadedKeyDetectors(): readonly KeyDetector[] {
    return DETECTORS;
}
