# @droidrun/redaction

Secret detection and redaction for text and JSON values, with the same rules
and placeholders for every consumer. The rules, including the formats that 0.2.0 took from secretlint,
are data in `../spec/` that this package interprets; secretlint is no longer a dependency (it is the test
oracle only). No consumer-side dependency patch is needed.

## Install

This package is private and published to GitHub Packages. Add to your project's `.npmrc`:

```ini
@droidrun:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

Provide `NODE_AUTH_TOKEN` through your secret manager using a GitHub token with
`read:packages` and access to this package, then install:

```sh
pnpm add @droidrun/redaction@0.2.0
```

For Docker, use a BuildKit secret instead of a build argument or a token stored in the image:

```dockerfile
# syntax=docker/dockerfile:1
COPY package.json pnpm-lock.yaml .npmrc ./
RUN --mount=type=secret,id=npm_token \
    NODE_AUTH_TOKEN=$(cat /run/secrets/npm_token) pnpm install --frozen-lockfile
```

Pass the secret with `docker build --secret id=npm_token,env=NODE_AUTH_TOKEN .`.

## Two entry points

| | sync | async (full) |
|---|---|---|
| Functions | `redactTextSync`, `redactJsonValueSync` | `redactText`, `redactJsonValue`, `detectSecrets` |
| Rules | the standard tier | the standard tier **plus** the full tier (the ported secretlint rules: AWS, GitHub, Slack, npm, 1Password, private keys, database connection strings, …) |
| Use for | logs, spans, error bodies, hot paths | stored user content, API read responses |
| Bounds | character, node and depth limits; **fails closed** | a 2 MB cap for the full-tier rules; a failure falls back to the sync rules |
| Budget | about 30 ms for 1,000 action rows | about 75 ms for 1,000 action rows |

The sync rules are the one rule source: the async path runs them over the whole text and
adds the full-tier rules (AWS, GitHub, Slack, npm, 1Password, database connection strings, …).
A secret both find is reported once; the earlier hit's rule id wins (the scanner's), so
`AWS_SECRET_ACCESS_KEY=…` is `[REDACTED:aws]` async and
`AWS_SECRET_ACCESS_KEY=[REDACTED:generic-keyword]` sync. The conformance vectors record both.
Object keys follow the tier too: the async path scans keys with the full rules, so a key that is itself an npm,
Slack, 1Password, … token becomes `[REDACTED:<rule>]` (compat and strict); the sync path reads keys with the standard
rules only.

```ts
import {
  redactJsonValue, redactJsonValueSync, redactText, redactTextSync, restoreRedacted,
} from '@droidrun/redaction';

// Sync: a log line or a span attribute.
redactTextSync('login password: Ab1!Ab1!').text; // login password: [REDACTED:generic-keyword]
redactTextSync('Authorization: Bearer abc.def').text; // Authorization: Bearer [REDACTED:auth-header]

// Sync: a JSON value (strings under secret-named keys are replaced).
redactJsonValueSync({ headers: { 'X-Api-Key': 'k-1', accept: 'json' } });
// { headers: { 'X-Api-Key': '[REDACTED:key-context]', accept: 'json' } }

// Async: stored user content before an API returns it.
const stats = { hits: [] };
const safe = await redactJsonValue(stored, stats);
```

### The `./sync` entry

`import { redactTextSync, redactJsonValueSync, restoreRedacted } from '@droidrun/redaction/sync'`
loads no full-tier code (a test enforces it): use it in loggers, spans and edge workers
where start-up and bundle size matter. It exports the sync redactors, `restoreRedacted`,
`isSecretKeyName`, `keyVerdict`, `STRUCTURAL_SKIP_KEYS`, `PLACEHOLDER_RE`, `buildPlaceholder`,
`buildReadPlaceholder` and `shortenRuleId`; the main entry re-exports all of them.

### Sync rules

Everything the sync path (and, inside it, the async path) detects:

- **Keywords**: `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `access_key`,
  `client_secret`, `private_key`, `credential(s)`, `authorization`, `bearer` followed by `:` or `=`
  and a value with evidence of being secret (three character classes or high entropy), and,
  without that test, `password`, `secret`, `api_key`, `access_token`, `auth_token` pairs (quoted
  values may contain spaces; an unterminated or over-long quote is redacted to the end of the
  text). Also inside **escaped JSON** (`{\"password\":\"…\"}`, any number of escaping layers).
  A value longer than 256 characters is redacted whole. Doc stand-ins (`your_key_here`), masks
  (`xxxx`, `****`) and trivial values (`undefined`, `changeme`) stay.
- **Authorization values**: `Bearer …`, `Basic …`, `Token …`. `Basic` and `Token` need a
  credential-looking value (8+ characters, not a plain or Capitalized word), and `Bearer` followed
  by prose (`token`, `auth`, `header`, `scheme`, `missing`, `invalid`, `required`, …) stays, so
  `Missing or invalid bearer token` and `Token expired` are unchanged.
- **Cookie header lines**: `Cookie:` and `Set-Cookie:` values (all cookies on the line).
- **URL query strings**: the whole value of a secret-named parameter (`?token=…`, `&api_key=…`,
  `&sig=…`, and `code`, `sid`, `session` which are secret in a query only), including a `?` or `&`
  inside it, however long. A non-secret parameter that hides a secret one is redacted whole:
  `redirect=https://y/?token=…` (the inner value) and the percent-encoded
  `redirect=https%3A%2F%2Fy%2F%3Ftoken%3D…` (decoded once). Decoding stops after 1,000,000
  characters of values per text.
- **URL userinfo**: the password in `scheme://user:password@host`.
- **Key formats**: PEM private key blocks (also with literal `\n`; a block without footer is
  redacted to the end of its body), JWT, Google API keys, xAI keys, OpenAI/Anthropic `sk-…`
  (needs a digit), Stripe `sk_`/`rk_` live and test keys, GitHub tokens, AWS access key ids,
  Slack tokens, Mobilerun `dr_sk_…` keys and `srt1.`/`srt2.` platform tokens.
- **Key names** (JSON): a key is secret when it holds the words `api key`, `access token`,
  `auth token`, `access key`, `password`, `secret`, `token`, `authorization`, `cookie`,
  `credential`, `private key`, `client key`, `passwd`, `passphrase`, `signature`, `card number`,
  `basic auth`, `priv key`, `signing key`, `encryption key`, `master key`, `ssh key`,
  `service account key`, `dsn`, `connection string`, `recovery code` as separate words
  (`clientSecret`, `x-auth-token`, `Set-Cookie`, `Proxy-Authorization`), ends in `pwd` or `pass`
  (`MYSQL_PWD`, `dbPass`), is a lower-case compound ending in or starting with one
  (`userpassword`, `secretkey`, `accesskeyid`), or is exactly `pwd`, `otp`, `totp`, `pin`, `cvv`,
  `cvc`, `sig`, `jwt`, `pass`, `auth`. Words match as such or as a plural, so `secretary`,
  `passwordless`, `tokenizer`, `passThrough` and the Twilio `sid` stay. `isSecretKeyName(key)` is exported, and so is `keyVerdict(key)`: `'none'`, `'string'` (strings are replaced, numbers stay: `max_tokens`, `tokens`) or `'any'` (numbers too: `pin`, `password`).

What a secret-named key does to the value below it:

- a **string** is replaced (`[REDACTED:key-context]`), also inside a container under the key;
- a **number** is replaced only under a singular secret key without a count word (`pin`, `token`,
  `password`); **counts stay**: `max_tokens`, `prompt_tokens`, `token_count`, `tokens: [1, 2]`;
- a **container** is walked, not replaced wholesale: its strings are replaced, its numbers follow
  the rule above, structural keys stay;
- `null`, booleans, empty strings and values that already are a placeholder stay;
- a key in the skip set (default `type`, `id`) keeps its **primitive** value byte for byte; a
  container under it is still walked. Object **keys** are scanned too: a key that holds a secret
  becomes a placeholder key.

### Sync API

- `redactTextSync(text, opts?)`: `{ text, hits }`. `opts.maxChars` (default 4,000,000): a longer
  text is replaced whole by `[REDACTED:size-limit]` (the limit applies before the short-text
  shortcut; no prefix is exposed). A non-string is turned into one (`String(x)`); it never throws.
- `redactJsonValueSync(value, opts?)`: the redacted copy; the input is never mutated. Options:
  `skipKeys`, `maxDepth` (64; deeper becomes `[REDACTED:depth-limit]`), `maxNodes` (500,000 values:
  every leaf and container counts; on exhaustion traversal stops and the rest becomes
  `[REDACTED:size-limit]`, keys beyond it are omitted), `maxChars` (4,000,000 across all strings; a leaf
  that does not fit is replaced whole), `stats` (`{ hits }` receives rule ids and ranges, never matched
  text). A circular reference becomes `[REDACTED:circular]`; typed arrays and buffers become
  `[REDACTED:size-limit]`; an `Error` is read as `{ name, message, stack }` and an object with
  `toJSON` through it, then scanned.
- Both never throw and fail **closed**: an internal failure replaces the value with
  `[REDACTED:redaction-failed]`.

### Async API (0.1.1 exports, plus)

- `detectSecrets(text, opts?)`: `Hit[]` (`{ ruleId, range: [start, end] }`, end-exclusive string
  indices, overlapping hits merged). Hits never include the matched text.
- `redactText(text, opts?)`: `{ text, hits }`. It never throws, including if the event callback
  fails. If the scanners fail it falls back to the sync rules (and to `[REDACTED:error]` for the
  whole text if those fail too): a scan failure never passes a secret.
- `RedactTextOpts`: optional `detect` override, `onEvent(name, attrs)` hook (events
  `redaction.scan.capped` and `redaction.detect.failed`; messages and input are never sent) and,
  new in 0.2.0, `last4` (below).
- `redactJsonValue(value, stats, opts?)`: recursively scans string leaves, appending findings to
  `stats.hits`; the key rules above apply at every depth. `opts.skipKeys` (`ReadonlySet<string>`)
  **replaces** the default skip set, for example `{ skipKeys: new Set(['type', 'id', 'recordId']) }`;
  since 0.2.0 only primitive values under a skipped key are kept, containers are walked.
- `STRUCTURAL_SKIP_KEYS` (`type`, `id`). `CREDENTIAL_KEY_RE` is **deprecated**: the 0.1.1 substring
  matcher, kept unchanged for existing consumers (it also hits `secretary` and `tokenizer` and
  misses `x-auth-token`); use `isSecretKeyName`.

The full tier is the recommended secretlint 13.0.4 rule set, ported into the spec (`spec/INVENTORY.md`):
without the comment filter, so `secretlint-disable` comments cannot suppress findings, and without the
`gcp` rule; AWS key ids and account ids are on. The one difference from secretlint: an AWS secret access key is
reported over the secret itself, not from the key name. The JWT, Google, xAI and keyword rules that 0.1.1
ran as secretlint rules are the sync rules, with the same ids.

## Placeholders

`[REDACTED:<rule>]`, for every read route, log line and span: no character of the secret is
exposed. Rule names omit the `@secretlint/secretlint-rule-` / `mobilerun-redaction/` prefix;
overlapping hits merge into one span and keep the first rule's name. Sync rule ids:
`generic-keyword`, `auth-header`, `key-context` (decided by a key name or query parameter),
`cookie`, `url-credentials`, `private-key`, `jwt`, `gcp-api-key`, `xai-api-key`, `openai`, `stripe`,
`github`, `aws`, `slack`, `platform-token`, `platform-key`, and the limit markers `size-limit`,
`depth-limit`, `circular`, `redaction-failed`, `error`.

0.1.1 wrote `[REDACTED:<rule>:<last4>]` for matches of 16+ characters. That form is now opt-in
(`redactText(text, { last4: true })`, `redactJsonValue(v, stats, { last4: true })`;
`buildPlaceholder(ruleId, matched)` is unchanged, except that brackets in the last four
characters are masked as `*`). The bare `[REDACTED]` that triggers-api wrote is also recognised.

- `buildReadPlaceholder(ruleId)`: `[REDACTED:<rule>]`.
- `PLACEHOLDER_RE`: matches a string that **is** one placeholder of any of the three forms
  (anchored). One grammar backs every check: whatever `buildPlaceholder` emits, spaces in the
  last4 included, is a placeholder; a value that merely contains or starts with one is not.
- Redaction is idempotent: a placeholder is never redacted again.

## Restore

`restoreRedacted(incoming, stored, opts?)` is the write-side partner: a client that read redacted
values and sends the document back carries placeholders; this puts the stored values back.
**Editors are trusted with secrets** (whoever may edit and run a resource holds its secrets
anyway; redaction protects read-only roles, logs, spans and responses); restore only prevents
accidental loss or misplacement of a secret on a read-modify-write, so it does not bind a secret
to the fields around it: a changed `url` next to a placeholder still restores.

It returns `{ value, conflicts }`: `conflicts` lists the JSON path (`$.steps[1].with.token`) of
every placeholder that could **not** be restored; it stays in `value`. A caller rejects the write
or tells the client; nothing is dropped silently.

A placeholder keeps the stored value at the **same path** when that is a non-placeholder string,
number, object or array, and:

- **Matching.** Objects match by key. Array items match by **identity**: the `id` property by
  default, or `opts.identify(item)`; so deleting, inserting or reordering items cannot move a
  secret to another item. An identity that occurs more than once on either side is ambiguous
  and matches nothing (conflict). Items with no identity on either side match by **index only
  when both arrays have the same length**; otherwise the placeholder stays (conflict).
- **Strings.** An incoming string that contains placeholders keeps the **stored string** only
  if its literal segments appear in the stored string in order, the first at the start and the
  last at the end. Edited text around a placeholder is a conflict. A whole placeholder also
  restores a stored number, object or array (`[REDACTED]` replaced those in triggers-api; limit
  markers stand for subtrees).

Everything else takes `incoming` as sent: new keys and values win, removed keys are gone, and a
placeholder with nothing restorable behind it (missing, `null`, boolean, or a different
placeholder) stays a placeholder and is a conflict (a value is never invented). Legacy
`[REDACTED]` and `:last4` placeholders are recognised. Pure; neither argument is mutated. A key
named `__proto__` is an ordinary key.

```ts
const stored = await loadActionParams(id);                   // real values
const shown = await redactJsonValue(stored, { hits: [] });   // what the API returns
const { value, conflicts } = restoreRedacted(clientBody.params, stored);
if (conflicts.length > 0) throw badRequest('re-enter these values', conflicts);
```

## Conformance vectors

`spec/vectors/*.json` (in the repo root; `prepack` copies them into the package)
hold the cases every implementation must agree on, so the Go and Python ports (and each consumer's
tests) can run the same file:

```json
{ "description": "…", "cases": [
  { "name": "bearer header", "input": "Authorization: Bearer abc.def-1=",
    "expected": "Authorization: Bearer [REDACTED:auth-header]" },
  { "name": "url userinfo", "input": "postgres://admin:hunter2secret@db.example.com:5432/app",
    "expectedSync": "postgres://admin:[REDACTED:url-credentials]@db.example.com:5432/app",
    "expectedAsync": "[REDACTED:database-connection-string]" } ] }
```

A string `input` runs through the text entry point, anything else through the JSON entry point.
`expected` is the output of both entries; a case where the async path is more specific carries
`expectedSync` and `expectedAsync` instead. Files: `keywords`, `auth-headers`, `key-names`,
`key-formats`, `nested-json`, `url-query`, `base64`, `false-positives` (ordinary text that must stay
unchanged), `modes` (the `compat` and `strict` failure modes with the `maxChars`, `maxDepth` and
`maxNodes` limits). A case may set `mode` and `opts`. The files are published with the package and
importable as `@droidrun/redaction/vectors/<name>.json`. `src/vectors.test.ts` is the loader.

## Modes

`mode: 'compat'` (the default) is what 0.2.0 does. `mode: 'strict'` is an additive option on
`redactTextSync`, `redactJsonValueSync`, `redactText` and `redactJsonValue`: it never returns text
that was not scanned. A failing scanner replaces the whole text (`[REDACTED:error]`), the part of a
text beyond the 2,000,000-character scan cap becomes `[REDACTED:size-limit]`, and JSON is walked
without recursion within `maxDepth`, `maxNodes` and `maxChars` (the async entries take them in the
options too); whatever it cannot scan is a placeholder. Strings under `skipKeys` (default `type`, `id`)
are scanned too (the skip keys only exempt them from the key-name replacement). The rules and their
semantics are in [`../spec/SPEC.md`](../spec/SPEC.md).

## Limits

- Secrets split across different string leaves are not reassembled or detected.
- Skipped primitive values (`type`, `id`) are never scanned, even if they contain a secret.
- The full-tier rules see the first 2,000,000 characters of each leaf; beyond that only the sync rules
  run (fail closed for the sync formats, documented gap for full-tier-only formats).
- Short, unlabeled passwords in free text are not detected; a secret-named key provides the context
  to redact such a value.
- Keys are only scanned for secrets, not renamed otherwise; two keys that become the same
  placeholder collapse into one.
- The sync path replaces a text or leaf over its limit whole; a restore cannot bring that back
  (it is a conflict).
- Latency (1,000 realistic action rows, about 0.5 MB of JSON, measured on an Apple-silicon laptop):
  sync about 30 ms, async about 75 ms. `src/perf.test.ts` enforces 250 ms (sync) and 1,500 ms
  (async) as the median of five runs. `src/adversarial.test.ts` runs worst-case texts (64 KB to
  200 KB, measured 20 to 70 ms; the CI runner is about 5x slower) against a 1,000 ms budget each, so a
  quadratic rule (seconds to minutes on these inputs) fails the build.

## Development and release

Requires Node.js 22 or later, pnpm 10.18.1, and Bun for tests. Run the commands in this directory
(`ts/`).

```sh
pnpm install --frozen-lockfile
pnpm run typecheck
pnpm test
pnpm run build
```

The rules are data: this package runs on `src/spec-data.generated.ts`, a module generated from `../spec/`
by `../tools/sync-spec` (no file access or Node built-in at runtime, so every entry also runs in edge
runtimes), and refuses to import on an unsupported version or an empty rule set. CI and the release run
`../tools/sync-spec --check`, and `src/spec-integrity.test.ts` proves the module equals `../spec/`. Change a
rule in `../spec/`, then run `../tools/sync-spec`. The conformance vectors are copied into the package by
`prepack`. `src/golden.test.ts` replays a seeded corpus of 12,000+ inputs and requires the
output recorded from the unchanged package at commit b12879a, byte for byte.

`@secretlint/core`, `@secretlint/secretlint-rule-preset-recommend` and `@secretlint/types` (all `13.0.4`)
are development dependencies: the oracle of `src/secretlint-parity.test.ts`, which requires the same
(rule id, range) pairs as the preset in both directions on the upstream fixtures, the golden corpus and
seeded near-misses (one documented AWS deviation). `tools/check-pack.ts` verifies that the packed package
imports no `@secretlint` module. The suite also runs the conformance vectors on both
entries, a seeded fuzz test (3,000 sync and 600 async cases per family: no leak of an injected
marker in values, keys, escaped JSON, URL userinfo, nested queries, cookies; idempotence; restore
round trip, also after deleting, inserting and reordering items), the perf and adversarial budgets,
a 0.1.1 export-compat test, the golden replay, and the spec-integrity tests.

After merge, a `v<version>` tag (for example `v0.2.0`) triggers publishing to GitHub Packages. The workflow
checks the tag against `package.json`, requires the tagged commit to be on `main`,
runs typecheck and tests, and uses `GITHUB_TOKEN` with `packages:write`.
