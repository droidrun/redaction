/**
 * Text secret detection and replacement. `redactText` is the shared entry
 * point for plain text and the JSON-value visitor. Detector failures return
 * the original text and no hits; consumers never lose data to a scan failure.
 */
import { scanText, type EngineHit } from './engine.js';
import { buildPlaceholder } from './placeholder.js';

export type Hit = EngineHit;

/** Below this, not worth invoking the engine — no real secret is <8 chars. */
const MIN_SCAN_LEN = 8;

/**
 * Scan window size — a single string this long or shorter is scanned in one
 * `scanText` call, byte-for-byte identical to the pre-chunking behavior.
 * Longer strings are walked in overlapping windows of this size (see
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
 * cap simply isn't scanned (documented trade-off, not a bug) — the cap
 * itself is logged via a counter so a systematic miss would show up in
 * telemetry rather than silently.
 */
const MAX_TOTAL_SCAN_LEN = 2_000_000;

/** Sort ascending by start, then MERGE overlapping/touching ranges into their
 *  union — two rules firing on overlapping spans (e.g. an AWS-shaped match
 *  plus a generic-keyword match starting mid-way through it) must never be
 *  spliced independently (that would corrupt the string) NOR have the later
 *  one silently dropped (that would leave the un-covered tail of the union
 *  — real secret material — unredacted). The merged hit keeps the ruleId of
 *  the earliest-starting hit in the group; `applyRedactions` then builds the
 *  placeholder from the FULL merged span, so the last4-threshold in
 *  `buildPlaceholder` correctly sees the union's length, not either
 *  constituent hit's length alone. */
function dedupeRanges(hits: readonly Hit[]): Hit[] {
    const sorted = [...hits].sort((a, b) => a.range[0] - b.range[0]);
    const merged: Hit[] = [];
    for (const hit of sorted) {
        const [start, end] = hit.range;
        const last = merged[merged.length - 1];
        const overlapsPrevious = last !== undefined && start <= last.range[1];
        if (overlapsPrevious) {
            if (end > last.range[1]) {
                merged[merged.length - 1] = { ruleId: last.ruleId, range: [last.range[0], end] };
            }
            continue;
        }
        merged.push({ ruleId: hit.ruleId, range: [start, end] });
    }
    return merged;
}

/**
 * Unconditional, length-guarded secretlint scan. No flag-gating, no
 * fail-open (a throw here is expected to propagate to `redactText`, the one
 * place that owns the fail-open contract).
 *
 * For text at or below `MAX_SCAN_LEN`, this is a single `scanText` call —
 * identical to the pre-chunking behavior. Longer text is walked in
 * overlapping `MAX_SCAN_LEN`-sized windows (stride = `MAX_SCAN_LEN -
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

    if (scanLen <= MAX_SCAN_LEN) {
        return scanText(text.slice(0, scanLen));
    }

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

/** Replace every (deduped) hit with its placeholder, walking from the END of
 *  the string backward — each splice only touches indices at-or-after its
 *  own start, so earlier (lower-index, not-yet-processed) ranges in `out`
 *  are still at their ORIGINAL positions when their turn comes. */
function applyRedactions(text: string, hits: readonly Hit[]): string {
    const deduped = dedupeRanges(hits);
    let out = text;
    for (let i = deduped.length - 1; i >= 0; i--) {
        const hit = deduped[i];
        if (!hit) continue;
        const [start, end] = hit.range;
        const matched = text.slice(start, end);
        out = out.slice(0, start) + buildPlaceholder(hit.ruleId, matched) + out.slice(end);
    }
    return out;
}

export type RedactTextOpts = {
    /** Overrides the detector — for the fail-open/exception-message-leak
     *  test only. */
    detect?: (text: string) => Promise<Hit[]>;
    /** Receives safe scan metadata. Callback failures cannot interrupt redaction. */
    onEvent?: (name: string, attrs: Record<string, unknown>) => void | Promise<void>;
};

function emitEvent(opts: RedactTextOpts, name: string, attrs: Record<string, unknown>): void {
    try {
        const pending = opts.onEvent?.(name, attrs);
        if (pending) {
            void Promise.resolve(pending).catch(() => {});
        }
    } catch {
        // Observability must never break the fail-open contract.
    }
}

/**
 * Detect + replace. NEVER THROWS: a detector failure logs a warning (with NO
 * exception-message passthrough — an exception's `message` could itself
 * echo a slice of the very input that broke the regex engine, which would
 * turn the failure-logging path into a secret-logging path) and returns the
 * ORIGINAL text unredacted rather than losing the caller's data. Warnings
 * are delivered only through the optional `onEvent` callback.
 */
export async function redactText(
    text: string,
    opts: RedactTextOpts = {},
): Promise<{ text: string; hits: Hit[] }> {
    try {
        const hits = opts.detect ? await opts.detect(text) : await detectSecrets(text, opts);
        if (hits.length === 0) return { text, hits: [] };
        return { text: applyRedactions(text, hits), hits };
    } catch (err) {
        // Deliberately omit err.message — see doc comment above.
        emitEvent(opts, 'redaction.detect.failed', {
            errorName: err instanceof Error ? err.constructor.name : typeof err,
        });
        return { text, hits: [] };
    }
}
