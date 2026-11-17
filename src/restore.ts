/**
 * restore.ts — `restoreRedacted(incoming, stored)`: the write-side partner of
 * redaction. A client that read redacted values and writes the document back
 * sends placeholders; this puts the stored values back where a placeholder
 * came in, so a read-modify-write never destroys a secret.
 *
 * Walks both values in step, like the JSON redactors do:
 *   - `incoming` is a string that IS or CONTAINS a placeholder (`[REDACTED]`,
 *     `[REDACTED:<rule>]`, `[REDACTED:<rule>:<last4>]`) and `stored` holds a
 *     string at that position: the STORED string is kept, whole. Edits to the
 *     text around a placeholder inside one string are therefore not applied;
 *     to change such a string, send it without the placeholder.
 *   - `incoming` is exactly a placeholder and `stored` holds a number, object
 *     or array there (a whole value replaced under a secret-named key): the
 *     stored value is kept.
 *   - objects: every key of `incoming` is kept; a key present in both is
 *     restored recursively; a key only in `incoming` is new and wins as sent;
 *     a key only in `stored` is gone (the client removed it).
 *   - arrays are matched by index; extra incoming items are new.
 *   - everything else, and every position where `stored` has no matching
 *     value, takes `incoming` as sent. A value is never invented: a
 *     placeholder with nothing stored behind it stays a placeholder.
 * Pure; never mutates its arguments.
 */
import { PLACEHOLDER_ANYWHERE_RE, PLACEHOLDER_RE } from './placeholder.js';
import { setOwnKey } from './own-key.js';

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function restoreString(incoming: string, stored: unknown): unknown {
    if (typeof stored === 'string') {
        return PLACEHOLDER_ANYWHERE_RE.test(incoming) ? stored : incoming;
    }
    const wholeValueReplaced = typeof stored === 'number' || typeof stored === 'bigint' ||
        (typeof stored === 'object' && stored !== null);
    return wholeValueReplaced && PLACEHOLDER_RE.test(incoming) ? stored : incoming;
}

export function restoreRedacted(incoming: unknown, stored: unknown): unknown {
    if (typeof incoming === 'string') return restoreString(incoming, stored);
    if (Array.isArray(incoming)) {
        const storedItems = Array.isArray(stored) ? stored : [];
        return incoming.map((item, index) => restoreRedacted(item, storedItems[index]));
    }
    if (!isRecord(incoming)) return incoming;
    const storedRecord = isRecord(stored) ? stored : {};
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(incoming)) {
        const hasStored = Object.hasOwn(storedRecord, key);
        setOwnKey(out, key, hasStored ? restoreRedacted(value, storedRecord[key]) : value);
    }
    return out;
}
