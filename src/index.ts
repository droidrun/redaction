export { detectSecrets, redactText, type Hit, type RedactTextOpts } from './redact-text.js';
export {
    redactJsonValue,
    type RedactValueStats,
    STRUCTURAL_SKIP_KEYS,
    CREDENTIAL_KEY_RE,
} from './redact-value.js';
export { buildPlaceholder, shortenRuleId, PLACEHOLDER_RE } from './placeholder.js';
