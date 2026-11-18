/**
 * sync.ts — the `@droidrun/redaction/sync` entry: the sync redactors, restore,
 * key-name and placeholder helpers, with NO secretlint import. Use it where
 * start-up and bundle cost matter (loggers, spans, edge workers); the full
 * entry (`@droidrun/redaction`) re-exports all of this plus the async path.
 */
export {
    redactJsonValueSync,
    redactTextSync,
    type RedactJsonSyncOpts,
    type RedactTextSyncOpts,
} from './redact-sync.js';
export {
    restoreRedacted,
    type RestoreOpts,
    type RestoreResult,
} from './restore.js';
export { isSecretKeyName, STRUCTURAL_SKIP_KEYS } from './key-names.js';
export type { Hit } from './hits.js';
export { buildPlaceholder, buildReadPlaceholder, shortenRuleId, PLACEHOLDER_RE } from './placeholder.js';
export type { RedactMode } from './mode.js';
