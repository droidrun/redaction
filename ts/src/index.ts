export { detectSecrets, redactText, type Hit, type RedactTextOpts } from './redact-text.js';
export {
    redactJsonValue,
    type RedactValueStats,
    type RedactValueOpts,
    STRUCTURAL_SKIP_KEYS,
    CREDENTIAL_KEY_RE,
} from './redact-value.js';
export {
    redactJsonValueSync,
    redactTextSync,
    type RedactJsonSyncOpts,
    type RedactTextSyncOpts,
} from './redact-sync.js';
export { restoreRedacted, type RestoreOpts, type RestoreResult } from './restore.js';
export { isSecretKeyName, keyVerdict, type KeyVerdict } from './key-names.js';
export { buildPlaceholder, buildReadPlaceholder, shortenRuleId, PLACEHOLDER_RE } from './placeholder.js';
export type { RedactMode } from './mode.js';
