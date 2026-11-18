# secretlint 13.0.4 rule fixtures

Test fixtures of the 26 secretlint rules that the full tier ports (SPEC.md section 9.4,
INVENTORY.md), copied unchanged from the upstream repository, read-only:

- repository: https://github.com/secretlint/secretlint
- tag: `v13.0.4`
- commit: `725e479e0e7b2f760400d0140c317c60cd4e8849`
- source directories: `packages/@secretlint/secretlint-rule-<rule>/test/snapshots/`

Each `<rule>/<case>/` holds the fixture input (`input`, `input.txt`, `input.json`, or a named
file such as `.npmrc`), the upstream expected result (`output.json`: rule id, message id and
range of every report) and, where the case needs options, `.secretlintrc.json` or `options.ts`.

Not copied: the rules `gcp` and `filter-comments` (not ported, decided 2026-11-18) and the rules
that are not in the preset. Cases that need options (`allows`, `enableIDScanRule: false`) or a
file name other than `message.txt` are kept for completeness; `ts/src/secretlint-parity.test.ts`
runs the others and checks them against the recorded upstream result and against the full tier.

Licence of the fixtures: MIT (secretlint).
