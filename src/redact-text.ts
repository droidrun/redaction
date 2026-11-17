/**
 * Text secret detection and replacement. `redactText` is the shared entry
 * point for plain text and the JSON-value visitor. Detector failures return
 * the original text and no hits; consumers never lose data to a scan failure.
 */
import { scanText } from './engine.js';
import { applyHits, dedupeRanges, type Hit } from './hits.js';
import { detectSyncHits } from './sync-rules.js';

export type { Hit };

/** Below this, not worth invoking the engine — no real secret is <8 chars. */
const MIN_SCAN_LEN = 8;

/**
 * Scan window size — a single string this long or shorter is scanned in one
 * `scanText` call. Longer strings are walked in overlapping windows of this size (see
 * `detectSecrets`) rather than truncated, so a secret anywhere in the
 * string — not just its first 100k chars — gets caught.
 */
const MAX_SCAN_LEN = 100_000;

/**
 * Overlap between consecutive scan windows. Must be at least as large as the
 * biggest contiguous secret the ruleset can match — a secret straddling a
 * window boundary needs the FULL match to fall within at least one window's
 * contiguous text; the regex can't be satisfied by unioning a partial match
 * from each side, and `dedupeRanges` can only merge two ranges that were
 * each already a complete hit.
 *
 * `10_240` covers every BOUNDED match in the ruleset: the widest is
 * `@secretlint/secretlint-rule-privatekey`'s PEM body pattern (`{100,10000}`
 * for the base64 body, plus header/footer/newline slack), so a full PEM
 * block can be ~10k+ chars — every custom rule here and every provider-key
 * shape from the upstream preset is far shorter than that.
 *
 * Residual gap (disclosed, not fixed by any overlap size): a few rules use
 * UNBOUNDED quantifiers — the custom JWT rule's `[\w-]{10,}` segments and
 * `generic-keyword-rule`'s `{8,}` value capture. A pathological match from
 * one of those longer than this overlap, straddling a window boundary,
 * could still be missed. This is a low-severity trade-off: both rule
 * families are keyword/structure-gated (a JWT needs 3 dot-separated
 * base64url segments; generic-keyword needs a credential-shaped label
 * immediately before the value), so a legitimate match realistically stays
 * far under 10k chars — nothing in real traffic exercises this edge.
 */
const SCAN_OVERLAP = 10_240;

/**
 * Absolute ceiling on how much of one string leaf is ever scanned, even with
 * chunking — a screenshot/base64 blob pasted into a tool-output string can
 * be multi-MB, and secretlint's regex rules would otherwise re-run their
 * full match sweep over an unbounded amount of content per message. A real
 * pasted credential is never anywhere near this long; anything beyond the
 * cap simply isn't scanned (documented trade-off, not a bug). The cap is
 * reported as the `redaction.scan.capped` event.
 */
const MAX_TOTAL_SCAN_LEN = 2_000_000;

export type RedactTextOpts = {
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
 * Unconditional, length-guarded scan: the secretlint scanners plus the sync
 * rules (`sync-rules.ts`), so the async path finds everything the sync path
 * does. Errors propagate to `redactText`, which owns the fail-open contract.
 *
 * For text at or below `MAX_SCAN_LEN`, this is a single `scanText` call.
 * Longer text is walked in overlapping `MAX_SCAN_LEN`-sized windows
 * (stride = `MAX_SCAN_LEN -
 * SCAN_OVERLAP`) up to `MAX_TOTAL_SCAN_LEN`, so the TAIL of a long string
 * (e.g. a large raw file-read tool output) is scanned too, not silently
 * dropped. Each window's hit ranges are offset back to ABSOLUTE indices
 * before merging, and `dedupeRanges` collapses the resulting overlaps (a
 * secret straddling a window boundary is reported once per window it falls
 * in, fully or partially — the union still covers it completely).
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
    const scanLen = capped ? MAX_TOTAL_SCAN_LEN : text.length;
    const scanned = capped ? text.slice(0, scanLen) : text;
    const scannerHits = await scanWindows(scanned);
    return [...scannerHits, ...uncoveredSyncHits(scannerHits, detectSyncHits(scanned))];
}

/** Sync hits a scanner hit does not already contain, so a secret both find is
 *  reported once, under the scanner's rule id. */
function uncoveredSyncHits(scannerHits: readonly Hit[], syncHits: readonly Hit[]): Hit[] {
    if (scannerHits.length === 0) return [...syncHits];
    return syncHits.filter((hit) => !scannerHits.some((scanner) => {
        return scanner.range[0] <= hit.range[0] && hit.range[1] <= scanner.range[1];
    }));
}

/** The secretlint scanners over `text` (already capped), in windows when long. */
async function scanWindows(text: string): Promise<Hit[]> {
    const scanLen = text.length;
    if (scanLen <= MAX_SCAN_LEN) return scanText(text);

    const stride = MAX_SCAN_LEN - SCAN_OVERLAP;
    const allHits: Hit[] = [];
    for (let offset = 0; offset < scanLen; offset += stride) {
        const windowEnd = Math.min(offset + MAX_SCAN_LEN, scanLen);
        const window = text.slice(offset, windowEnd);
        const windowHits = await scanText(window);
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
 * Returns the original text unredacted rather than losing the caller's data.
 */
export async function redactText(
    text: string,
    opts: RedactTextOpts = {},
): Promise<{ text: string; hits: Hit[] }> {
    try {
        const hits = opts.detect ? await opts.detect(text) : await detectSecrets(text, opts);
        if (hits.length === 0) return { text, hits: [] };
        return { text: applyHits(text, hits, opts.last4 === true), hits };
    } catch (err) {
        // Deliberately omit err.message — see doc comment above.
        emitEvent(opts, 'redaction.detect.failed', {
            errorName: err instanceof Error ? err.constructor.name : typeof err,
        });
        return { text, hits: [] };
    }
}
