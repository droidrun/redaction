# redaction

Secret detection and redaction for text and JSON values. One language-neutral spec, one
implementation per language, identical output.

| directory | what | status |
|---|---|---|
| [`spec/`](spec) | the rules, word lists, thresholds and algorithms as data (`rules.json`, `keys.json`, `algorithms.json`), the normative [`SPEC.md`](spec/SPEC.md), JSON Schemas, conformance vectors, the recorded golden corpus, and [`INVENTORY.md`](spec/INVENTORY.md) (the secretlint rules and how each was ported) | this slice |
| [`ts/`](ts) | `@droidrun/redaction` for Node/Bun, reads its rules from a copy of `spec/` | this slice |
| [`python/`](python) | `droidrun-redaction`, the standard and the full tier ([`python/README.md`](python/README.md)) | this slice |
| [`go/`](go) | `github.com/droidrun/redaction/go`, both tiers ([`go/README.md`](go/README.md)) | this slice |
| [`tools/`](tools) | `lint-spec`, `sync-spec`, `gen-letters`, the corpus generator, the pack check, the cross-language differential test (`tools/diff`), `release-version` | this slice |

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
- `tools/diff` is the differential test: the same 19,000+ seeded cases (corpus families, every vector,
  the secretlint fixtures, the attack units at small sizes, random mixes with astral characters and lone
  surrogates) go through a TypeScript, a Python and a Go runner over one JSONL protocol
  ([`tools/diff/protocol.ts`](tools/diff/protocol.ts)), and the outputs must be byte-identical (key
  order counts, numbers are compared as doubles, hits as rule-id counts). Each runner prints its
  capabilities first, so a tier a language does not have yet is skipped and is checked automatically as
  soon as that language gets it. CI runs it as the `differential` job.

## Commands

```sh
bun tools/diff/driver.ts                       # differential test (needs ts/, tools/ and python/ installed, go on the PATH)
bun test tools/diff                            # the driver's own tests
tools/release-version --check                  # npm, Python and Go carry one version
cd ts && pnpm install --frozen-lockfile && pnpm run typecheck && pnpm test && pnpm run build
cd tools && pnpm install --frozen-lockfile    # recheck, ajv for lint-spec
bun tools/lint-spec.ts                         # needs python3 and go on the PATH
bun tools/lint-spec.ts --self-test             # plants non-portable patterns, expects failures
tools/sync-spec --check                        # generated spec files up to date
bun tools/check-pack.ts                        # npm pack and import from the tarball
bun tools/gen-letters.ts --check               # the Unicode 15.0.0 letter table (downloads UnicodeData.txt; CI runs it weekly and on release, not per pull request)
```

The TypeScript package is documented in [`ts/README.md`](ts/README.md).

## Releasing

One version number for all three packages: `ts/package.json` (npm), `python/pyproject.toml` (with its
entry in `python/uv.lock`) and the `Version` constant of `go/version.go`. CI checks on every pull request
that they are equal (`tools/release-version --check`).

1. **Bump PR.** On a branch from `main`: `tools/release-version X.Y.Z`, commit (`chore(redaction): release
   X.Y.Z`), open a PR, get it reviewed and merged into `main`. Nothing else changes in that PR.
2. **Tag.** Push the tag `vX.Y.Z` on the merge commit (`git tag vX.Y.Z <sha> && git push origin vX.Y.Z`). Only
   the owner pushes release tags.
3. **The workflow** (`publish.yml`, trigger: tag `v*`) checks that the tag equals the version of all three
   packages, that the commit is on `main`, then `sync-spec --check`, typecheck, tests, build, `lint-spec`,
   `gen-letters --check` (Unicode table) and `check-pack`. Then it pushes the tag `go/vX.Y.Z` on the same
   commit (the Go module lives in `go/`, so its tag carries the `go/` prefix) and publishes the npm package.
   A re-run finds an existing `go/vX.Y.Z` on the same commit and goes on; on another commit it fails.
4. **Python** is not published to an index. Consumers pin the full commit SHA of the release commit
   (`rev = "<40-character SHA>"`, `subdirectory = "python"`, see [`python/README.md`](python/README.md)).
5. **Go** consumers use `github.com/droidrun/redaction/go@vX.Y.Z`.

