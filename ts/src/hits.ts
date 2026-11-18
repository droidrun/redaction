/**
 * hits.ts — merging detector hits and splicing placeholders into a string.
 * Shared by the async (`redact-text.ts`) and the sync (`redact-sync.ts`) path,
 * so both produce the same output for the same hits.
 */
import { buildPlaceholder, buildReadPlaceholder } from './placeholder.js';

export type Hit = { ruleId: string; range: readonly [number, number] };

/** Sort ascending by start, then MERGE overlapping/touching ranges into their
 *  union — two rules firing on overlapping spans (e.g. an AWS-shaped match
 *  plus a generic-keyword match starting mid-way through it) must never be
 *  spliced independently (that would corrupt the string) NOR have the later
 *  one silently dropped (that would leave the un-covered tail of the union
 *  — real secret material — unredacted). The merged hit keeps the ruleId of
 *  the earliest-starting hit in the group (the first listed on equal starts);
 *  the placeholder is then built from the FULL merged span. */
export function dedupeRanges(hits: readonly Hit[]): Hit[] {
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

/** Replace every (merged) hit with its placeholder. `last4` selects the
 *  0.1.1 form `[REDACTED:<rule>:<last4>]` for long matches; the default is the
 *  read/log form without any character of the secret. */
export function applyHits(text: string, hits: readonly Hit[], last4 = false): string {
    const parts: string[] = [];
    let cursor = 0;
    for (const hit of dedupeRanges(hits)) {
        const [start, end] = hit.range;
        parts.push(text.slice(cursor, start));
        const placeholder = last4
            ? buildPlaceholder(hit.ruleId, text.slice(start, end))
            : buildReadPlaceholder(hit.ruleId);
        parts.push(placeholder);
        cursor = end;
    }
    parts.push(text.slice(cursor));
    return parts.join('');
}

/** Append every hit of `source` to `target` (a loop: spreading a long list into `push` overflows). */
export function appendHits(target: Hit[], source: readonly Hit[]): void {
    for (const hit of source) target.push(hit);
}
