# @droidrun/redaction

Secret detection and redaction for text and JSON values, with the same rules
and placeholders for every consumer. Runs the pinned secretlint scanners directly;
`@secretlint/core` and `@secretlint/profiler` are absent from the runtime import graph.
No consumer-side dependency patch is needed.

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
| Rules | deterministic regex rules only | the sync rules **plus** the secretlint scanners |
| Use for | logs, spans, error bodies, hot paths | stored user content, API read responses |
| Bounds | depth, node and character limits; **fails closed** | scan windows and a 2 MB cap; **fails open** |
| Budget | about 20 ms for 1,000 action rows | about 75 ms for 1,000 action rows |

The async path finds everything the sync path finds, and more. A secret both
find is reported once; the scanner's rule id wins (for example
`AWS_SECRET_ACCESS_KEY=…` is `[REDACTED:aws]` async and
`AWS_SECRET_ACCESS_KEY=[REDACTED:generic-keyword]` sync).

```ts
import {
  redactJsonValue, redactJsonValueSync, redactText, redactTextSync, restoreRedacted,
} from '@droidrun/redaction';

// Sync: a log line or a span attribute.
redactTextSync('login password: Ab1!Ab1!').text; // login password: [REDACTED:generic-keyword]
redactTextSync('Authorization: Bearer abc.def').text; // Authorization: Bearer [REDACTED:auth-header]

// Sync: a JSON value (secret-named keys are replaced as a unit).
redactJsonValueSync({ headers: { 'X-Api-Key': 'k-1', accept: 'json' } });
// { headers: { 'X-Api-Key': '[REDACTED:key-context]', accept: 'json' } }

// Async: stored user content before an API returns it.
const stats = { hits: [] };
const safe = await redactJsonValue(stored, stats);
```

### Sync rules

Everything the sync path (and, as its first half, the async path) detects:

- **Keywords**: `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `access_key`,
  `client_secret`, `private_key`, `credential(s)`, `authorization`, `bearer` followed by
  `:` or `=` and a value with evidence of being secret (three character classes or high
  entropy), and, without that test, `password`, `secret`, `api_key`, `access_token`,
  `auth_token` pairs (quoted values may contain spaces). Doc stand-ins (`your_key_here`),
  masks (`xxxx`, `****`) and trivial values (`undefined`, `changeme`) stay.
- **Authorization values**: `Bearer …`, `Basic …`, `Token …`. `Basic` and `Token` need a
  credential-looking value (8+ characters, not a plain or Capitalized word), so
  `Token expired` and `Basic information` stay.
- **URL query strings**: the value of `?token=…`, `&api_key=…`, `&sig=…` and any other
  secret-named parameter; the rest of the query stays.
- **Key formats**: JWT, Google API keys, xAI keys, GitHub tokens, AWS access key ids, Slack
  tokens, Mobilerun platform tokens (`srt1.` / `srt2.`).
- **Key names** (JSON): a key is secret when it holds the words `api key`, `access token`,
  `auth token`, `access key`, `password`, `secret`, `token`, `authorization`, `cookie`,
  `credential`, `private key`, `client key`, `passwd`, `passphrase`, `signature`,
  `card number` as separate words (`clientSecret`, `x-auth-token`, `Set-Cookie`,
  `Proxy-Authorization`), is a lower-case compound ending in one (`userpassword`), or is
  exactly `pwd`, `otp`, `totp`, `pin`, `cvv`, `cvc`, `sig`, `sid`, `jwt`. Words match as
  such or as a plural, so `secretary`, `passwordless` and `tokenizer` stay.
  `isSecretKeyName(key)` is exported.

A string, number or whole object or array under a secret-named key is replaced as a unit;
`null`, booleans, empty strings and values that already are a placeholder stay. A key in
the skip set (default `type`, `id`) and everything below it is never touched.

### Sync API

- `redactTextSync(text, opts?)`: `{ text, hits }`. `opts.maxChars` (default 4,000,000):
  text beyond it is cut and replaced by `[REDACTED:size-limit]`.
- `redactJsonValueSync(value, opts?)`: the redacted copy; the input is never mutated.
  Options: `skipKeys` (replaces the default `type`/`id` set), `maxDepth` (64; deeper becomes
  `[REDACTED:depth-limit]`), `maxNodes` (100,000) and `maxChars` (4,000,000 across all
  strings; beyond either becomes `[REDACTED:size-limit]`), `stats` (`{ hits }` receives rule
  ids and ranges, never matched text). A circular reference becomes `[REDACTED:circular]`.
- Both never throw. They fail **closed**: an internal failure replaces the value with
  `[REDACTED:redaction-failed]`. Hits carry `{ ruleId, range }` only.

### Async API (unchanged from 0.1.1, plus)

- `detectSecrets(text, opts?)`: returns `Hit[]` (`{ ruleId, range: [start, end] }`,
  end-exclusive string indices); applies the scan limits and propagates detector errors.
  Hits never include the matched text.
- `redactText(text, opts?)`: `{ text, hits }`. Detection failures return the original text
  and empty hits; it never throws, including if the event callback fails.
- `RedactTextOpts`: optional `detect` override, `onEvent(name, attrs)` hook (events
  `redaction.scan.capped` and `redaction.detect.failed`; messages and input are never sent)
  and, new in 0.2.0, `last4` (below).
- `redactJsonValue(value, stats, opts?)`: recursively scans string leaves, appending
  findings to `stats.hits`; the key-name rule above applies at every depth. `opts.skipKeys`
  (`ReadonlySet<string>`) **replaces** the default skip set, for example
  `{ skipKeys: new Set(['type', 'id', 'recordId']) }`.
- `STRUCTURAL_SKIP_KEYS` (`type`, `id`), `CREDENTIAL_KEY_RE` (the 0.1.1 substring matcher,
  kept for consumers that use it themselves; the walkers use the word matcher above).

The scanners are the recommended secretlint rules (without the comment filter, so
`secretlint-disable` comments cannot suppress findings; AWS ID scanning on) plus the JWT,
credential-shaped key/value, Google and xAI rules.

## Placeholders

`[REDACTED:<rule>]`, for every read route, log line and span: no character of the secret
is exposed. Rule names omit the `@secretlint/secretlint-rule-` / `mobilerun-redaction/`
prefix; overlapping hits merge into one span and keep the first rule's name. Sync rule ids:
`generic-keyword`, `auth-header`, `key-context` (decided by a key name or query parameter),
`jwt`, `gcp-api-key`, `xai-api-key`, `github`, `aws`, `slack`, `platform-token`, and the
limit markers `size-limit`, `depth-limit`, `circular`, `redaction-failed`.

0.1.1 wrote `[REDACTED:<rule>:<last4>]` for matches of 16+ characters. That form is now
opt-in (`redactText(text, { last4: true })`, `redactJsonValue(v, stats, { last4: true })`;
`buildPlaceholder(ruleId, matched)` is unchanged). The bare `[REDACTED]` that triggers-api
wrote is also recognised.

- `buildReadPlaceholder(ruleId)`: `[REDACTED:<rule>]`.
- `PLACEHOLDER_RE`: matches a string that **is** one placeholder of any of the three
  forms (anchored). `PLACEHOLDER_ANYWHERE_RE`: the same marker inside a longer string.
- Redaction is idempotent: a placeholder is never redacted again.

## Restore

`restoreRedacted(incoming, stored)` is the write-side partner: a client that read redacted
values and sends the document back carries placeholders; this puts the stored values back.

- `incoming` string that **is or contains** a placeholder, and `stored` holds a string
  there: the **stored string** is kept, whole. Edits to the text around a placeholder
  inside that one string are not applied; to change it, send it without a placeholder.
- `incoming` is exactly a placeholder and `stored` holds a number, object or array there
  (a value replaced as a unit under a secret-named key): the stored value is kept.
- Objects: every key of `incoming` is kept; keys in both are restored recursively; a key only
  in `incoming` is new and wins; a key only in `stored` is gone (the client removed it).
- Arrays are matched by index; extra incoming items are new. Reordering an array that holds
  placeholders therefore restores by position, not by identity.
- Anything else, and every position with nothing stored behind it, takes `incoming` as sent.
  A value is never invented: a placeholder with no stored value stays a placeholder.
- Pure; neither argument is mutated. A key named `__proto__` is an ordinary key.

```ts
const stored = await loadActionParams(id);                  // real values
const shown = await redactJsonValue(stored, { hits: [] });  // what the API returns
const toSave = restoreRedacted(clientBody.params, stored);  // what the API stores
```

## Conformance vectors

`vectors/*.json` hold the cases every implementation must agree on, so the Go and Python
ports (and each consumer's tests) can run the same file:

```json
{ "description": "…", "cases": [
  { "name": "bearer header", "input": "Authorization: Bearer abc.def-1=",
    "expectedSync": "Authorization: Bearer [REDACTED:auth-header]",
    "expectedAsync": "Authorization: Bearer [REDACTED:auth-header]" } ] }
```

A string `input` runs through the text entry point, anything else through the JSON entry
point. Files: `keywords`, `auth-headers`, `key-names`, `key-formats`, `nested-json`,
`url-query`, `base64`, `false-positives` (ordinary text that must stay unchanged). The
files are published with the package and importable as
`@droidrun/redaction/vectors/<name>.json`. `src/vectors.test.ts` is the loader.

## Limits

- Secrets split across different string leaves are not reassembled or detected.
- Skip-key fields are never scanned or force-redacted, even if they contain a secret.
- The async path scans 100,000-character windows with 10,240 overlap and the first
  2,000,000 characters of each leaf; a match with an unbounded quantifier that exceeds the
  overlap and crosses a window boundary can be missed. The sync path has no windows but its
  own character limit (above).
- Short, unlabeled passwords in free text are not detected; a secret-named key provides the
  context to redact such a value.
- Keys are not redacted, only values. A secret used as a key name stays.
- Async detector errors fail open, preserving the original unredacted input; the sync path
  fails closed.
- Latency (1,000 realistic action rows, about 0.5 MB of JSON, measured on an Apple-silicon
  laptop): sync about 20 ms, async about 75 ms. `src/perf.test.ts` enforces 250 ms (sync) and
  1,500 ms (async) as the median of five runs, leaving headroom for slow CI.

## Development and release

Requires Node.js 22 or later, pnpm 10.18.1, and Bun for tests.

```sh
pnpm install --frozen-lockfile
pnpm run typecheck
pnpm test
pnpm run build
```

The exact `13.0.4` pins of `@secretlint/secretlint-rule-preset-recommend` and
`@secretlint/types` are load-bearing: dependency bumps need green parity and rule-shape guard tests.
Parity tests use `@secretlint/core` only as a development dependency. A separate
process verifies that importing the public entry and scanning a 300 kB input
loads neither core nor the profiler. The suite also runs the conformance vectors, a
seeded fuzz test (3,000 sync and 600 async cases each: no leak of an injected marker,
idempotence, restore round trip), the perf budget, and a 0.1.1 export-compat test.

After merge, a `v<version>` tag (for example `v0.2.0`) triggers publishing to GitHub Packages. The workflow
checks the tag against `package.json`, requires the tagged commit to be on `main`,
runs typecheck and tests, and uses `GITHUB_TOKEN` with `packages:write`.
