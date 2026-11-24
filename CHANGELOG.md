# Changelog

## Unreleased

Preparation for making the repository public. No change to what is detected, except where noted.

- **`pii` option (new, off by default).** `pii: true` on the text and JSON entry points (sync and async, both modes)
  also redacts emails, phone numbers, IPv4/IPv6 addresses and OTP codes in prose, as `[REDACTED:email]`,
  `[REDACTED:phone]`, `[REDACTED:ip]` and `[REDACTED:otp]` (spec sections 4.19 to 4.22, vectors in `spec/vectors/pii.json`).
  Without the option the output is unchanged. TypeScript only in this slice: Python and Go follow with the same vectors.
- **Short secrets in `strict` (TypeScript so far).** In `strict`, text pairs use the key verdict of JSON keys: `password=x`,
  `token=hunter2`, `DB_PASS=hunter2`, `signing_key=abc` and `{"password":"x"}` are redacted, also with escaped quotes
  (`{\"token\":\"x\"}`) and the separators `=>` and `:=`; `token: expired` and a number under a count key
  (`max_tokens: 5`) stay. A pair inside the value of another (`auth: password: hunter2`, YAML parents) is found, and a value
  never starts after a line break. `dr_sk_` keys are redacted in any case and length, and the whole `Bearer` credential (up
  to whitespace or a quote). A text or object key of any length is scanned in `strict` and with `pii`. `strict` redacts at
  least everything 0.3.0 `strict` redacted (the old pair rules still run), except that after `=>` or `:=` a stand-in value
  stays. `compat` is byte-identical to before (golden corpus). Consumers that run `strict` redact more after the bump.
- **`restoreRedacted` knows strict and `pii` keys.** A key that was replaced in `strict` or with `pii` maps back to its
  stored key; a placeholder key that two stored keys could stand for stays a conflict.

- **MIT license.** `LICENSE` at the root and in `ts/`, `python/` and `go/`; license fields in the npm and Python
  metadata; the wheel and the npm package carry `LICENSE` and `NOTICE`.
- **Third-party notices.** `THIRD_PARTY_NOTICES.md` (also `NOTICE` in each package): secretlint 13.0.4 (MIT; the full
  tier is ported from its rules, the fixtures in `spec/corpus/secretlint-13.0.4/` come from it) and the Unicode 15.0.0
  data of the letter table.
- **Install docs for a public repository.** Python over https (`git+https://github.com/droidrun/redaction.git@<sha>`),
  Go through the public Go proxy without `GOPRIVATE`; npm stays on GitHub Packages (needs a `read:packages` token).
- **Platform token rule.** The kind part of the `srt2` token is any lower-case word instead of a fixed list, so it
  redacts the same tokens or more.
- **Repository hygiene.** Internal names removed from comments, docs and tests; decision notes keep their dates, not
  their ids; `SECURITY.md`; `.github/secret_scanning.yml` for the synthetic fixtures; the CI uv is pinned to a newer
  version.

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
