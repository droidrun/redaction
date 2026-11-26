# redaction (Go)

`github.com/droidrun/redaction/go` finds secrets in text and JSON values and replaces them with
placeholders such as `[REDACTED:generic-keyword]`. It is the Go interpreter of the
language-neutral [spec](../spec) and gives the same output as the TypeScript package
(`@droidrun/redaction`), in both tiers (see [Tiers](#tiers)). Standard library only, no cgo, no
dependencies.

## Install

```sh
go get github.com/droidrun/redaction/go@v0.4.1   # resolved through the tag go/v0.4.1
```

The module lives in the `go/` directory, so its tags are `go/vX.Y.Z`
([Go modules reference](https://go.dev/ref/mod#vcs-version)). Go 1.26 or newer.

## API

```go
import redaction "github.com/droidrun/redaction/go"

text, result := redaction.RedactText(line, redaction.Options{})

out, result, err := redaction.RedactJSON(body, redaction.Options{}) // compact JSON; err is ErrInvalidJSON

redaction.IsSecretKeyName("x-auth-token") // true

// the full tier: the standard rules plus key formats, connection strings, private keys, ...
text, result = redaction.RedactText(line, redaction.Options{Tier: redaction.TierFull})
```

- `RedactText(s string, opts Options) (string, Result)` redacts one text.
- `RedactJSON(data []byte, opts Options) ([]byte, Result, error)` redacts one JSON value. A string
  leaf is scanned; a string under a secret-named key (`password`, `apiKey`, `x-auth-token`, ...)
  is replaced whole; so is a number under a singular secret key (`pin`, not `max_tokens`).
  Object keys that hold a secret are redacted too; when two different keys of one object end up with
  the same key (two connection strings, two tokens, two keys over the limit, two `password=...` keys),
  no value is lost: a key that redaction leaves unchanged keeps its own name (reserved, wherever it
  stands in the object); a changed key whose name is taken gets a number inside its last placeholder,
  `[REDACTED:npm]`, `[REDACTED:npm#2]`, `#3`, ... (`token [REDACTED:npm#2]`), in the order of the object,
  skipping names that are taken. Output is compact JSON, object keys in
  ECMAScript order (integer-like keys first), a repeated key keeps its last value, numbers that are
  not replaced are written back exactly as they appeared (`1.0` stays `1.0`; the spec compares
  numbers as doubles, so the other languages may write `1`). Input that is not one JSON value gives `ErrInvalidJSON` and, as the output,
  the `RedactText` redaction of the raw input (with its `Result`): never the input itself, never
  nil, so a caller that logs the output on error cannot leak. The error never quotes the input.
- `IsSecretKeyName(key string) bool` is the key-name predicate of the spec.
- `KeyVerdict(key string) Verdict` is what a key makes of its values: `VerdictNone`,
  `VerdictString` (strings are replaced, numbers kept: `tokens`, `max_tokens`) or `VerdictAny`
  (strings and numbers are replaced: `password`, `pin`).
- `RedactField(key string, value any) any` redacts one attribute value by its key, for log and
  span handlers: a string under a secret key becomes `[REDACTED:key-context]`, any other string is
  scanned, a number is replaced only under `VerdictAny` (counts such as `max_tokens` stay), every
  other type is returned as it is.
- `Options{Tier, Mode, PII, SkipKeys, MaxDepth, MaxNodes, MaxChars}`; `Tier` is `TierStandard` (the zero
  value) or `TierFull`; `PII` is [below](#personal-data-the-pii-option); a nil limit is the spec default and an
  explicit one is used as given, so `redaction.Limit(0)` is a limit of zero (as in the TypeScript
  package). `SkipKeys` replaces the default skip keys (`type`, `id`); nil keeps them, an empty
  slice skips nothing.
- `Result{Hits []RuleCount; Err string}` with `RuleCount{RuleID string; Count int}`. It holds rule
  ids and counts only; ranges are not exposed because they reveal lengths. `Err` is the class of
  the first fail-closed event of the call (`size-limit`, `depth-limit`, `redaction-failed`,
  `error`) or empty; the output is safe either way.

Redacted output keeps the text around the hits byte for byte. Input that is not valid UTF-8 is
read with each invalid byte as one U+FFFD (never skipped), and the output holds that U+FFFD.

### Logging with slog

```go
handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
	ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
		return slog.Any(attr.Key, redaction.RedactField(attr.Key, attr.Value.Resolve().Any()))
	},
})
slog.New(handler).Info("login", "password", "hunter2xx", "max_tokens", 100)
// level=INFO msg=login password=[REDACTED:key-context] max_tokens=100
```

`ReplaceAttr` runs on every non-group attribute, so strings are scanned and secret keys are
replaced; `example_test.go` runs this.

## Tiers

- `TierStandard` (the zero value): the rules of the standard tier (generic keyword pairs, auth
  headers, cookies, URL credentials and query values, JWTs, PEM blocks, a few key formats).
- `TierFull`: the standard rules plus the **full-tier rules**, the ported secretlint preset
  (`@secretlint/secretlint-rule-preset-recommend` 13.0.4): AWS keys, private keys, npm, basic-auth
  URLs, Slack, SendGrid, Shopify, Stripe, GitHub, GitLab, Grafana, OpenAI, Anthropic, Groq, Hugging
  Face, Linear, Notion, 1Password, database connection strings (MongoDB, MySQL, PostgreSQL), HashiCorp
  Vault, Vercel, Databricks, Docker, Figma, Cloudflare, Tailscale. The hit of a full-tier rule is named
  by its rule id (`npm`, `privatekey`, ...). It is the same output as the TypeScript async entry points.
  What is not ported (`gcp`, `filter-comments`, the two npm branches that need a file name) is listed in
  [`spec/INVENTORY.md`](../spec/INVENTORY.md). The AWS secret access key is reported over the secret
  itself (SPEC 4.17).
- The full-tier rules see the first 2,000,000 units of a text, in windows of 100,000 units that overlap
  by 10,240 (each window is a text of its own); the standard rules always see the whole text. Compat
  scans a longer text with the standard rules beyond that cap; Strict replaces the units beyond the cap
  by `[REDACTED:size-limit]`.
- `RedactField` and the key rules (`IsSecretKeyName`, `KeyVerdict`) are the same in both tiers. In
  `RedactJSON` an object key (from 8 units in `Compat` without `PII`, from 1 in `Strict` and with `PII`, up to 4,096) is scanned with the rules of the tier: in the
  full tier a key that is itself a token (npm, Slack, 1Password, ...) is replaced by its placeholder,
  in both modes.

## Modes

- `Strict` (the zero value, the default): no path returns text that was not scanned. A text over
  `MaxChars`, a value beyond `MaxDepth` or `MaxNodes`, an over-long key or an internal failure
  gives `[REDACTED:size-limit]`, `[REDACTED:depth-limit]` or `[REDACTED:redaction-failed]`. A
  string under a skip key is scanned like any other. The JSON walk is iterative: nesting costs no
  stack. In the full tier a failing scanner replaces the whole text (or the leaf) by
  `[REDACTED:error]`.
- `Compat` reproduces the TypeScript package's default mode (a skip-key value is kept as it is, an
  over-long key is left as it is). In the full tier it has **no length, depth or node limit**
  (SPEC 9.4, as in the TypeScript package: `MaxChars`, `MaxDepth` and `MaxNodes` are not used), and a
  failing scanner falls back to the standard rules, then to `[REDACTED:error]`. Use Compat only to
  match old output.

In `Strict` the same key names that decide JSON keys also decide **text pairs** (`key: value`,
`key=value`, `key => "value"`, `key := "value"`, also inside escaped JSON): a value under a key with
the `VerdictAny` verdict is redacted even when it is short (`password=x`, `DB_PASS=hunter2`), under
`VerdictString` unless it is all digits (`max_tokens: 5`). Stand-ins (`changeme`, `xxxx`, `<token>`),
the words `expired`, `required`, `failed`, `missing`, `invalid`, `true`, `false`, `null`, `none` (up to
64 units) and, under an authorization key, the scheme words `Bearer`, `Basic`, `Digest` stay. A
value never starts after a line break, and a pair inside the value of another (`auth: password:
hunter2`) is found. `Strict` also redacts `dr_sk_` keys in any case and length and the whole `Bearer`
credential up to whitespace or a quote, and scans a text or key of any length. It redacts at least
everything the 0.3.0 `Strict` redacted; `Compat` does none of this.

## Personal data: the `PII` option

`Options{PII: true}` (default false), in both tiers and both modes, also redacts in prose and in JSON
strings and keys:

| rule id | what | stays |
|---|---|---|
| `email` | `person@example.com`, `A.B+tag@Example.CO.uk` | `react@18.2.0`, `icon@2x.png`, `user@localhost` |
| `phone` | `+44 20 7946 0958`, `(415) 555-0123`, `415-555-0123`, `020 7946 0958`, `01 99 00 12 34` | `Request ID 1234567890`, `2026-11-19 10:00:59`, `v0.3.0` |
| `ip` | IPv4 `192.0.2.123`, IPv6 `2001:db8::1`, `[fdab::cafe]:8080` (the address only, a port stays) | `version 1.2.3.4`, `android 14.0.0.1`, `999.1.1.1`, `std::vector` |
| `otp` | the digits after a code noun (`Your verification code is 482913`, `OTP code: 482913`) | `error code 5000`, `exit code 1370`, `response code 200000`, `port 8080` |

The placeholders are `[REDACTED:email]`, `[REDACTED:phone]`, `[REDACTED:ip]` and `[REDACTED:otp]`; a text
of any length is scanned. Names, postal addresses, IDN emails, URL-encoded values and prose secrets such
as `password hunter2` are not detected; the rules are in SPEC sections 4.19 to 4.22 and 15.

## Limits

Defaults come from the spec (`spec/algorithms.json`): 4,000,000 UTF-16 units per text or in total
per JSON value, depth 64, 500,000 values, keys up to 4,096 units. Lengths and offsets count UTF-16
code units, as the TypeScript package does (an astral character is two units).

`RedactJSON` enforces the limits while it reads the input: what the walk would cut is only checked
for syntax, so a call allocates a bounded amount (about 100 bytes per node up to the node limit,
and in strict mode the string content up to the character limit) however large the input is.
Compat keeps strings whole, as the TypeScript package does, so there its memory follows the size
of the strings. Strict charges every string against the character limit while it reads, including
one under a secret-named key (the walk replaces it for free), so a document with more than the
limit in strings can lose strings to `[REDACTED:size-limit]` a little earlier than the TypeScript
package does.

Matching uses Go's `regexp` (RE2, linear time). The spec patterns are written in a portable
grammar that RE2 reads the same way as JavaScript and Python.

## Differences from the TypeScript package

- **Lone surrogates in text.** A Go string cannot hold a lone surrogate. When a hit boundary falls between the
  two units of a valid surrogate pair (a bounded run of a rule cuts an astral character in half, for example the
  query part of a connection string at its 500th unit), the TypeScript package keeps the lone half in the
  output; `RedactText` gives U+FFFD for it. `RedactJSON` writes a lone surrogate as an escape (`\ude00`) and so
  keeps it, as TypeScript does. Input that is not valid UTF-8 is read with each invalid byte as U+FFFD.
- **Numbers.** Numbers that are not replaced are written as they appeared; TypeScript writes the double.
- **An out-of-range `Options.Tier`** is read as `TierFull`.
- The strict character limit is charged while the JSON is read (see Limits).

## Not supported yet

- `restoreRedacted` (restoring values from a stored copy).

## Integrity

The package embeds a copy of `rules.json`, `keys.json` and `algorithms.json` (`go:embed`) and a
generated hash constant (`spec_hash_gen.go`). At start-up it checks the hash, the spec version and
that the rule set is not empty, and panics with a generic message otherwise, so it processes no
input from a broken copy. `tools/sync-spec` writes the copy and the constant from `spec/`;
`tools/sync-spec --check` runs in CI.

## Tests

```sh
cd go
go vet ./... && gofmt -l .
go test -race ./...                      # vectors, golden replay, unicode, strict, integrity
go test -run TestAttackStrings ./...     # scaling at 100 KB and 1 MB, and the per-part run memory (not under -race)
go test -run XXX -fuzz FuzzRedactText -fuzztime 60s
go test -run XXX -fuzz FuzzRedactJSON -fuzztime 60s
go test -run XXX -bench . ./...          # a 2 KB log line and a 4 MB text, both tiers
(cd testdata/consumer && go run .)       # build from outside the module, public API only
```

`vectors_test.go` runs every case of `spec/vectors/*.json` on both tiers (the sync side is the
standard tier, the async side the full tier); `golden_test.go` replays
`spec/corpus/golden-b12879a.json.gz` against the recorded output of the TypeScript package, both
sides, but for the cases of three decisions: the AWS secret access key (reported over the secret), object
keys that are full-tier secrets (replaced by their placeholder in the full tier), and object keys that end up
with the same key (numbered, so no value is lost: 120 recorded cases on each side). The tests name every such
case and check that nothing else differs. `testdata/attacks.json` is written by `bun go/testdata/gen-attacks.ts` from
`tools/lib/attacks.ts` (plain and composite attacks).
