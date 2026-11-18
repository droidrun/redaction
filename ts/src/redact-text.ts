/**
 * Text secret detection and replacement. `redactText` is the shared entry
 * point for plain text and the JSON-value visitor. A scanner failure falls
 * back to the deterministic rules (see `redactText`); it never passes a secret.
 */
import { detectFullHits, withLegacyId } from './full-rules.js';
import { applyHits, dedupeRanges, type Hit } from './hits.js';
import type { RedactMode } from './mode.js';
import { buildReadPlaceholder } from './placeholder.js';
import { ALGORITHMS_SPEC } from './spec.js';
import { detectSyncHits } from './sync-rules.js';

export type { Hit };

const ERROR_RULE_ID = ALGORITHMS_SPEC.ruleIds.error;

/** Below this, not worth invoking the engine — no real secret is shorter. */
const MIN_SCAN_LEN = ALGORITHMS_SPEC.text.minScanLength;

/**
 * Scan window size: a text this long or shorter is scanned by the full-tier rules in one pass. A longer one is
 * scanned in overlapping windows (see `detectSecrets`) rather than truncated, so a secret anywhere in it is
 * caught. The overlap must be at least as large as the biggest contiguous secret of the full tier (the PEM body,
 * about 10k). The cap is the ceiling on how much of one text the full-tier rules see; the standard rules run over
 * the whole text, and a text beyond the cap is reported as the `redaction.scan.capped` event. Values: spec `full`.
 */
const FULL = ALGORITHMS_SPEC.full;
const MAX_SCAN_LEN = FULL.scanWindow;
const SCAN_OVERLAP = FULL.scanOverlap;
const MAX_TOTAL_SCAN_LEN = FULL.scanCap;

export type RedactTextOpts = {
    /** `strict` never passes an unscanned text: a scanner failure replaces the whole text and the
     *  part beyond the scan cap becomes `[REDACTED:size-limit]`. Default `compat`. */
    mode?: RedactMode;
    /** `strict` only: a longer text is replaced whole by `[REDACTED:size-limit]` (default 4,000,000). */
    maxChars?: number;
    /** Use the 0.1.1 placeholder `[REDACTED:<rule>:<last4>]` for matches of at least
     *  16 characters. Default: `[REDACTED:<rule>]`, which exposes nothing of the secret. */
    last4?: boolean;
    /** Overrides the detector. */
    detect?: (text: string) => Promise<Hit[]>;
    /** Receives safe scan metadata. Callback failures cannot interrupt redaction. */
    onEvent?: (name: string, attrs: Record<string, unknown>) => void | Promise<void>;
};

function emitEvent(opts: RedactTextOpts, name: string, attrs: Record<string, unknown>): void {
    // Observability must never break the fail-open contract.
    void (async () => opts.onEvent?.(name, attrs))().catch(() => {});
}

/**
 * Unconditional, length-guarded scan: the full-tier rules of the spec plus the standard rules
 * (`sync-rules.ts`), so the async path finds everything the sync path does. Errors propagate to `redactText`,
 * which owns the fail-open contract. Overlapping hits are merged.
 *
 * The full-tier rules see the first `MAX_TOTAL_SCAN_LEN` characters, in overlapping windows when longer than
 * `MAX_SCAN_LEN` (offsets are mapped back to absolute indices; a secret straddling a boundary is covered by the
 * union). The standard rules run over the WHOLE text, so past the cap only the full-tier-only formats are not
 * found; a text that long is reported as `redaction.scan.capped`.
 */
export async function detectSecrets(text: string, opts: RedactTextOpts = {}): Promise<Hit[]> {
    if (text.length < MIN_SCAN_LEN) return [];

    const capped = text.length > MAX_TOTAL_SCAN_LEN;
    if (capped) {
        emitEvent(opts, 'redaction.scan.capped', {
            originalLength: text.length,
            scannedLength: MAX_TOTAL_SCAN_LEN,
        });
    }
    const scanned = capped ? text.slice(0, MAX_TOTAL_SCAN_LEN) : text;
    return dedupeRanges([...scanWindows(scanned).map(withLegacyId), ...detectSyncHits(text)]);
}

/** The full-tier rules over `text` (already capped), in windows when long. */
function scanWindows(text: string): Hit[] {
    const scanLen = text.length;
    if (scanLen <= MAX_SCAN_LEN) return detectFullHits(text);

    const stride = MAX_SCAN_LEN - SCAN_OVERLAP;
    const allHits: Hit[] = [];
    for (let offset = 0; offset < scanLen; offset += stride) {
        const windowEnd = Math.min(offset + MAX_SCAN_LEN, scanLen);
        const windowHits = detectFullHits(text.slice(offset, windowEnd));
        for (const hit of windowHits) {
            allHits.push({ ruleId: hit.ruleId, range: [hit.range[0] + offset, hit.range[1] + offset] });
        }
        if (windowEnd >= scanLen) break;
    }
    return dedupeRanges(allHits);
}

/**
 * Detect + replace. NEVER THROWS: a detector failure emits
 * `redaction.detect.failed` without the exception message, because it could
 * echo a slice of the input that broke the engine and leak secret material.
 * It then falls back to the deterministic rules alone (`[REDACTED:error]` for
 * the whole text if those fail too): a failing scanner never passes a secret.
 */
export async function redactText(
    text: string,
    opts: RedactTextOpts = {},
): Promise<{ text: string; hits: Hit[] }> {
    if (opts.mode === 'strict') return redactTextStrict(text, opts);
    try {
        const hits = opts.detect ? await opts.detect(text) : await detectSecrets(text, opts);
        if (hits.length === 0) return { text, hits: [] };
        return { text: applyHits(text, hits, opts.last4 === true), hits };
    } catch (err) {
        // Deliberately omit err.message — see doc comment above.
        emitEvent(opts, 'redaction.detect.failed', {
            errorName: err instanceof Error ? err.constructor.name : typeof err,
        });
        return degradedRedaction(text);
    }
}

/** The scanners failed: the deterministic rules still run, and if they fail too
 *  the text is replaced. A scan failure never lets a secret through. */
function degradedRedaction(text: string): { text: string; hits: Hit[] } {
    try {
        const hits = detectSyncHits(text);
        return { text: applyHits(text, hits), hits };
    } catch {
        const hit: Hit = { ruleId: ERROR_RULE_ID, range: [0, 0] };
        return { text: buildReadPlaceholder(ERROR_RULE_ID), hits: [hit] };
    }
}

/** Strict: no fallback and no unscanned rest. A text over `maxChars` is replaced whole; a failure replaces
 *  the whole text; what lies beyond the scan cap is replaced by `[REDACTED:size-limit]` (merged with any hit
 *  it overlaps). `last4` is ignored: no hit of the strict mode carries a character of the text. */
async function redactTextStrict(text: string, opts: RedactTextOpts): Promise<{ text: string; hits: Hit[] }> {
    const { sizeLimit } = ALGORITHMS_SPEC.ruleIds;
    if (text.length > (opts.maxChars ?? ALGORITHMS_SPEC.strict.maxChars)) {
        return {
            text: buildReadPlaceholder(sizeLimit),
            hits: [{ ruleId: sizeLimit, range: [0, text.length] }],
        };
    }
    try {
        const found = opts.detect ? await opts.detect(text) : await detectSecrets(text, opts);
        const rest: Hit[] = [];
        if (text.length > MAX_TOTAL_SCAN_LEN) {
            rest.push({ ruleId: sizeLimit, range: [MAX_TOTAL_SCAN_LEN, text.length] });
        }
        const hits = dedupeRanges([...found, ...rest]);
        if (hits.length === 0) return { text, hits: [] };
        return { text: applyHits(text, hits), hits };
    } catch (err) {
        emitEvent(opts, 'redaction.detect.failed', {
            errorName: err instanceof Error ? err.constructor.name : typeof err,
        });
        const hit: Hit = { ruleId: ERROR_RULE_ID, range: [0, 0] };
        return { text: buildReadPlaceholder(ERROR_RULE_ID), hits: [hit] };
    }
}
