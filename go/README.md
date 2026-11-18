# redaction (Go)

`github.com/droidrun/redaction/go` finds secrets in text and JSON values and replaces them with
placeholders such as `[REDACTED:generic-keyword]`. It is the Go interpreter of the
language-neutral [spec](../spec) and gives the same output as the TypeScript package
(`@droidrun/redaction`). Standard library only, no cgo, no dependencies.

## Install

The repository is private. Allow the Go tool to fetch it, then add the module:

```sh
export GOPRIVATE=github.com/droidrun/*
go get github.com/droidrun/redaction/go@go/vX.Y.Z   # a tag of the form go/vX.Y.Z
```

The module lives in the `go/` directory, so its tags are `go/vX.Y.Z`
([Go modules reference](https://go.dev/ref/mod#vcs-version)). Go 1.26 or newer.

## API

```go
import redaction "github.com/droidrun/redaction/go"

text, result := redaction.RedactText(line, redaction.Options{})

out, result, err := redaction.RedactJSON(body, redaction.Options{}) // compact JSON; err is ErrInvalidJSON

redaction.IsSecretKeyName("x-auth-token") // true
```

- `RedactText(s string, opts Options) (string, Result)` redacts one text.
- `RedactJSON(data []byte, opts Options) ([]byte, Result, error)` redacts one JSON value. A string
  leaf is scanned; a string under a secret-named key (`password`, `apiKey`, `x-auth-token`, ...)
  is replaced whole; so is a number under a singular secret key (`pin`, not `max_tokens`).
  Object keys that hold a secret are redacted too. Output is compact JSON, object keys in
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
- `Options{Mode, SkipKeys, MaxDepth, MaxNodes, MaxChars}`; a nil limit is the spec default and an
  explicit one is used as given, so `redaction.Limit(0)` is a limit of zero (as in the TypeScript
  package). `SkipKeys` replaces the default skip keys (`type`, `id`); nil keeps them, an empty
  slice skips nothing.
- `Result{Hits []RuleCount; Err string}` with `RuleCount{RuleID string; Count int}`. It holds rule
  ids and counts only; ranges are not exposed because they reveal lengths. `Err` is the class of
  the first fail-closed event of the call (`size-limit`, `depth-limit`, `redaction-failed`) or
  empty; the output is safe either way.

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

## Modes

- `Strict` (the zero value, the default): no path returns text that was not scanned. A text over
  `MaxChars`, a value beyond `MaxDepth` or `MaxNodes`, an over-long key or an internal failure
  gives `[REDACTED:size-limit]`, `[REDACTED:depth-limit]` or `[REDACTED:redaction-failed]`. A
  string under a skip key is scanned like any other. The JSON walk is iterative: nesting costs no
  stack.
- `Compat` reproduces the TypeScript package v0.2.0 for the standard tier (a skip-key value is
  kept as it is, an over-long key is left as it is). Use it only to match old output.

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

## Not supported yet

- The `full` tier (the secretlint preset); `Options` has no tier and only the standard tier runs.
  A full-tier port follows in a later slice and plugs into the same interpreter.
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
go test -run TestAttackStrings ./...     # scaling at 100 KB and 1 MB (not under -race)
go test -run XXX -fuzz FuzzRedactText -fuzztime 60s
```

`vectors_test.go` runs every case of `spec/vectors/*.json` on the standard tier; `golden_test.go`
replays `spec/corpus/golden-b12879a.json.gz` against the recorded output of the TypeScript
package. `testdata/attacks.json` is written by `bun go/testdata/gen-attacks.ts` from
`tools/lib/attacks.ts`.
