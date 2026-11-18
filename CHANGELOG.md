# Changelog

## 0.3.0

The redaction rules now live once, in a language-neutral spec, and three implementations follow it: TypeScript
(`@droidrun/redaction`), Python (`droidrun-redaction`) and Go (`github.com/droidrun/redaction/go`). For the
same input they give the same output, and CI checks that on every change.

### New

- **One spec, three languages.** `spec/` holds every rule, word list and threshold as data, with the exact
  algorithms in `spec/SPEC.md`. Python and Go are new; both have the standard and the full tier.
- **Full tier without secretlint.** The formats from the secretlint preset (AWS, GitHub, Slack, npm, 1Password,
  private keys, database connection strings, …) are ported into the spec. The package no longer needs secretlint
  at run time, so there are no runtime dependencies and no consumer-side patch.
- **Strict mode.** `mode: 'strict'` (an option in TypeScript; the default in Python and Go) never returns text
  that was not scanned: a failure, a cap or a limit gives a placeholder instead of the raw text. The default in
  TypeScript stays `compat`.
- **Keys follow the tier.** In the full tier an object key that is itself a token (an npm or Slack token, …) is
  redacted too.
- **Numbered key collisions.** When several keys of one object redact to the same key, no value is lost any more:
  the first keeps the plain key, the next ones become `[REDACTED:npm#2]`, `#3`, … (a key written as a
  placeholder keeps its name).
- **`restoreRedacted` maps keys.** A client that sends back a redacted key, numbered or not, gets the stored key
  back; a key without a match stays and is reported as a conflict.
- **`keyVerdict`** is exported next to `isSecretKeyName`.
- **Cross-language CI.** The same 19,000+ seeded cases run through the TypeScript, Python and Go
  implementations in CI and must give identical output; one version number for npm, Python and Go.

### Changes for TypeScript consumers of 0.2.0

- **AWS secret access keys** are reported over the secret itself, not from the key name. The placeholder text
  stays `[REDACTED:aws]`; only the covered range differs from secretlint.
- **Colliding keys are numbered** instead of the last value winning (see above). Code that relied on a collision
  dropping values will now see the extra keys.
- **Keys are scanned with the full rules** in the async path (see above).
- **No runtime dependencies.** `@secretlint/*` packages are development dependencies only; remove any patch you
  carried for them.
- Everything else is unchanged: exports, signatures, the `./sync` entry, the default failure modes and the
  placeholder strings.

### Upgrading

- npm: `pnpm add @droidrun/redaction@0.3.0`.
- Go: `go get github.com/droidrun/redaction/go@v0.3.0`.
- Python: pin the commit of the tag `v0.3.0` (see `python/README.md`); the package is not published to an index.
