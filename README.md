# redaction

Secret detection and redaction for text and JSON values. One language-neutral spec, one
implementation per language, identical output.

| directory | what | status |
|---|---|---|
| [`spec/`](spec) | the rules, word lists, thresholds and algorithms as data (`rules.json`, `keys.json`, `algorithms.json`), the normative [`SPEC.md`](spec/SPEC.md), JSON Schemas, conformance vectors, the recorded golden corpus, and [`INVENTORY.md`](spec/INVENTORY.md) (which secretlint rules can be ported) | this slice |
| [`ts/`](ts) | `@droidrun/redaction` for Node/Bun, reads its rules from a copy of `spec/` | this slice |
| [`python/`](python) | `droidrun-redaction`, the standard tier ([`python/README.md`](python/README.md)) | this slice |
| [`go/`](go) | `github.com/droidrun/redaction/go`, the standard tier ([`go/README.md`](go/README.md)) | this slice |
| [`tools/`](tools) | `lint-spec`, `sync-spec`, the corpus generator, the pack check | this slice |

## How it fits together

- A rule lives once, in `spec/`. A pattern is written in a portable grammar (SPEC.md section 2) that
  JavaScript, Python and Go read the same way; what a pattern cannot say is a named algorithm,
  specified step by step in SPEC.md and implemented in every language. No rule regex or word list
  is written in `ts/`, `python/` or `go/`.
- Each package embeds the spec (TypeScript: a generated module) and refuses to start on an empty rule
  set. `tools/sync-spec` generates the embedded form and its hash from `spec/`; `tools/sync-spec --check`
  fails CI and the release when one is stale.
- `tools/lint-spec` checks the spec: JSON Schemas, the grammar ban list, static ReDoS analysis
  (recheck), compilation in JavaScript, Python and Go, and a scaling test at 100 KB and 1 MB.
- `spec/vectors/*.json` are the conformance cases for both tiers and both modes. The golden corpus
  in `spec/corpus/` is the recorded output of the package before the move; the TypeScript test
  replays it byte for byte.

## Commands

```sh
cd ts && pnpm install --frozen-lockfile && pnpm run typecheck && pnpm test && pnpm run build
cd tools && pnpm install --frozen-lockfile    # recheck, ajv for lint-spec
bun tools/lint-spec.ts                         # needs python3 and go on the PATH
bun tools/lint-spec.ts --self-test             # plants non-portable patterns, expects failures
tools/sync-spec --check                        # generated spec files up to date
bun tools/check-pack.ts                        # npm pack and import from the tarball
```

The TypeScript package is documented in [`ts/README.md`](ts/README.md).
