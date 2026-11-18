/**
 * The failure mode of a redaction call. `compat` is what 0.2.0 does (the default):
 * the sync path fails closed, the full path falls back to the sync rules when its
 * scanners fail and leaves a text beyond the scan cap to the sync rules. `strict`
 * never returns text it did not scan: any internal error, cap or limit becomes an
 * error result or `[REDACTED:size-limit]` for the unscanned rest.
 */
export type RedactMode = 'compat' | 'strict';
