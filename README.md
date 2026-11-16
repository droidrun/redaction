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
pnpm add @droidrun/redaction@0.1.0
```

For Docker, use a BuildKit secret instead of a build argument or a token stored in the image:

```dockerfile
# syntax=docker/dockerfile:1
COPY package.json pnpm-lock.yaml .npmrc ./
RUN --mount=type=secret,id=npm_token \
    NODE_AUTH_TOKEN=$(cat /run/secrets/npm_token) pnpm install --frozen-lockfile
```

Pass the secret with `docker build --secret id=npm_token,env=NODE_AUTH_TOKEN .`.

## API

```ts
import { redactJsonValue, redactText, type RedactValueStats } from '@droidrun/redaction';

// Redact a JSON result before returning it from an MCP tool.
const result = { content: [{ type: 'text', text: 'password: Ab1!Ab1!' }] };
const stats: RedactValueStats = { hits: [] };
const safeResult = await redactJsonValue(result, stats);
// { content: [{ type: 'text', text: 'password: [REDACTED:generic-keyword]' }] }

// Redact a log string before passing it to your logger.
const safeLog = await redactText('login password: Ab1!Ab1!', {
  onEvent: (name, attrs) => console.warn(name, attrs),
});
console.log(safeLog.text); // login password: [REDACTED:generic-keyword]
```

- `detectSecrets(text, opts?)`: returns `Hit[]` (`{ ruleId, range: [start, end] }`,
  with end-exclusive JavaScript string indices). It applies the scan limits and
  propagates detector errors. Hits never include the matched text.
- `redactText(text, opts?)`: returns `{ text, hits }`. Detection failures return the
  original text and empty hits. It never throws, including if the event callback fails.
- `RedactTextOpts`: optional `detect` override and `onEvent(name, attrs)` hook.
  Without a hook nothing is logged. Events are `redaction.scan.capped`
  (`{ originalLength, scannedLength }`) and `redaction.detect.failed` (`{ errorName }`).
  Exception messages and input text are never sent to the hook. Hooks can return
  `void` or `Promise<void>`; synchronous throws and asynchronous rejections are ignored.
- `redactJsonValue(value, stats, opts?)`: recursively scans string leaves,
  appending findings to `stats.hits`. Credential-shaped keys force redaction of
  nonempty string values, including short passwords. Primitives pass through.
- `STRUCTURAL_SKIP_KEYS`: the minimal default skip set, exactly `type` and `id`,
  exported as `ReadonlySet<string>`. Keys such as `url` and `code` are scanned
  unless the consumer skips them. Pass `opts.skipKeys` as a
  `ReadonlySet<string>` to **replace** it. For example:
  `redactJsonValue(result, stats, { skipKeys: new Set(['type', 'id', 'recordId']) })`.
  Skipping a key preserves its entire value, including nested objects, at every depth.
- `CREDENTIAL_KEY_RE`: the shared credential-key matcher.
- `buildPlaceholder(ruleId, matched)`, `shortenRuleId(ruleId)`, `PLACEHOLDER_RE`:
  placeholder utilities. Types `Hit`, `RedactTextOpts`, `RedactValueOpts`, and
  `RedactValueStats` are exported.

Detection uses the recommended secretlint scanner rules, excluding the comment filter
so `secretlint-disable` comments cannot suppress findings. AWS ID scanning is enabled.
Additional rules cover JWTs, credential-shaped key/value text, Google API keys, and xAI API keys.

## Placeholders and limits

Matches of at least 16 characters become `[REDACTED:<rule>:<last4>]`;
shorter matches become `[REDACTED:<rule>]`. Rule names omit the
`@secretlint/secretlint-rule-` or `mobilerun-redaction/` prefix. Overlapping hits
merge into one span, keeping the first rule's name. The final four characters
of longer matches remain visible by design.

Leading byte order marks (BOMs), including at scan-window starts, preserve correct redaction ranges.

Known gaps:

- Secrets split across different string leaves are not reassembled or detected.
- Skip-key fields are never scanned or force-redacted, even if they contain a secret
  (for example, a token in a URL). Choose your skip set accordingly.
- Text is scanned in 100,000-character windows with 10,240-character overlap.
  A match using an unbounded quantifier (JWT segments or credential values) that
  exceeds that overlap and crosses a boundary can be missed.
- Only the first 2,000,000 characters (UTF-16 code units) of each leaf are scanned.
  Beyond that cap, text is preserved and the optional cap event is emitted.
- Short, unlabeled passwords in free text are not detected. A credential-shaped
  JSON key provides the context to redact such a value.
- Detector errors fail open, preserving the original unredacted input.

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
loads neither core nor the profiler.

After merge, a `v0.1.0` tag triggers publishing to GitHub Packages. The workflow
checks the tag against `package.json`, requires the tagged commit to be on `main`,
runs typecheck and tests, and uses `GITHUB_TOKEN` with `packages:write`.
