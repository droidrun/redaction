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
export { restoreRedacted } from './restore.js';
export { isSecretKeyName } from './key-names.js';
export {
    buildPlaceholder,
    buildReadPlaceholder,
    shortenRuleId,
    PLACEHOLDER_RE,
    PLACEHOLDER_ANYWHERE_RE,
} from './placeholder.js';
