# droidrun-redaction (Python)

Secret redaction for text and JSON values. This is the Python implementation of the **standard and the full tier**
of the redaction spec in [`spec/`](../spec/SPEC.md). It redacts byte for byte like the TypeScript
package `@droidrun/redaction`: the same rules, the same placeholders (`[REDACTED:<rule>]`), the same
limits. It has no runtime dependencies and needs Python 3.11 or newer.

## Install

The package is not on a package index. Add it as a git dependency over https, pinned to a full commit SHA, with
`subdirectory = "python"`. For release 0.3.0 the SHA is the commit of the tag `v0.3.0`
(`git rev-parse v0.3.0^{commit}`):

```toml
[project]
dependencies = ["droidrun-redaction"]

[tool.uv.sources]
droidrun-redaction = { git = "https://github.com/droidrun/redaction.git", rev = "<40-character SHA of the commit of tag v0.3.0>", subdirectory = "python" }
```

With pip: `pip install "droidrun-redaction @ git+https://github.com/droidrun/redaction.git@<40-character SHA>#subdirectory=python"`.

## API

```python
from droidrun_redaction import redact_json, redact_text, is_secret_key_name

result = redact_text("password=hunter2hunter2 and more")
result.value   # 'password=[REDACTED:generic-keyword] and more'
result.hits    # (RuleCount(rule_id='generic-keyword', count=1),)
result.error   # None

result = redact_json({"user": "a", "api_key": "k", "note": "Bearer abcdefgh12345"})
result.value   # {'user': 'a', 'api_key': '[REDACTED:key-context]', 'note': 'Bearer [REDACTED:auth-header]'}
```

- `redact_text(text, *, tier="standard", mode="strict", max_chars=None) -> RedactResult`
- `redact_json(value, *, tier="standard", mode="strict", skip_keys=None, max_depth=None, max_nodes=None, max_chars=None) -> RedactResult`
  - `value` is a parsed JSON value: `dict`, `list`, `str`, `int`, `float`, `bool`, `None`.
  - Strings are scanned. A string under a secret key name (`password`, `x-auth-token`, `clientSecret`, ...)
    is replaced whole, and so is a number under a singular secret key (`pin`; not `max_tokens`).
  - Keys that themselves hold a secret are redacted. When two or more keys of one object redact to the
    same text, no value is lost: the first keeps the key, each further one gets a number inside its last
    placeholder, `[REDACTED:npm]`, `[REDACTED:npm#2]`, `[REDACTED:npm#3]`, in iteration order. A key that
    only contains placeholders (`label [REDACTED:npm]`) gets the number in its last placeholder. Keys that
    redaction leaves unchanged keep their own name and are reserved first; only changed keys are numbered, and
    they skip reserved names. A numbered placeholder is a placeholder like the plain one (it is never
    redacted again).
  - Output keys keep the ECMAScript order (integer-like keys ascending first), as the TypeScript
    package returns them.
  - `skip_keys` (default `type` and `id`): a scalar under such a key is not replaced because of a secret
    parent key. In `strict` mode a string under a skip key is still scanned.
- `is_secret_key_name(key: str) -> bool`
- `key_verdict(key: str) -> Literal["none", "string", "any"]`: what the key makes of the value under it
  (`none`: nothing; `string`: a string is replaced; `any`: a number is replaced too).
- `RedactResult(value, hits, error)` is a frozen dataclass. `hits` is a tuple of
  `RuleCount(rule_id, count)` in order of first hit: **rule id and count only, never a range or any text**
  (ranges reveal lengths). `error` is `None` when every scan ran. Otherwise it is the class name of the
  first failure of a scan (never a message: it could echo the input), and `value` holds a placeholder for what
  could not be scanned: `[REDACTED:redaction-failed]` in the standard tier, `[REDACTED:error]` in the full tier
  (the whole text, or the JSON leaf). In the full tier's `compat` mode `error` is also set when the full-tier
  rules failed but the standard rules took over; check it before you send a result on.

### Logging filter

`redact_json` is a ready-made filter for structured log records: strings under secret key names are replaced,
counts are kept, and every other string is scanned.

```python
record = {"user": "u1", "api_key": "k-123", "max_tokens": 100, "prompt_tokens": 12, "pin": 4321}
redact_json(record).value
# {'user': 'u1', 'api_key': '[REDACTED:key-context]', 'max_tokens': 100, 'prompt_tokens': 12,
#  'pin': '[REDACTED:key-context]'}
```

`key_verdict("max_tokens")` is `"string"` (a number stays), `key_verdict("pin")` is `"any"` (a number is
replaced). `skip_keys` must be a collection of strings (a single `str` raises `TypeError`).

Every rule, word list, threshold and limit comes from the spec data embedded in the package.

## Tiers

- `standard` (default, for compatibility): the key formats, key-name context, URL credentials, PEM blocks and
  keyword pairs of SPEC section 4.
- `full`: the standard rules plus the ported secretlint preset (SPEC 4.11 to 4.17): AWS, PEM private keys,
  npm, basic-auth URLs, Slack, SendGrid, Shopify, Stripe, GitHub, GitLab, Grafana, OpenAI, Anthropic, Groq,
  Hugging Face, Linear, Notion, 1Password, database connection strings, Vault, Vercel, Databricks, Docker,
  Figma, Cloudflare, Tailscale. Use `tier="full"` for content that leaves your system. The full-tier rules
  scan the first 2,000,000 units of a text (in windows of 100,000 that overlap by 10,240); the standard rules
  always scan the whole text. In `strict` mode what lies beyond the scan cap becomes
  `[REDACTED:size-limit]`. Object keys are scanned with the rules of the tier too: in the full tier a key
  that is itself a token (npm, Slack, 1Password, ...) is replaced by its placeholder.

The letter guard in front of a key format uses the Unicode 15.0.0 letter table of the spec, never the
interpreter's own `unicodedata`.

## Modes

- `strict` (default): no path returns a value that was not scanned. A text or leaf over a limit, a depth or
  node limit, an over-long key, a value outside the JSON model (`NaN`, infinities, bytes, sets, tuples,
  class instances, non-string keys) and any internal failure give a placeholder
  (`[REDACTED:size-limit]`, `[REDACTED:depth-limit]`, `[REDACTED:circular]`,
  `[REDACTED:redaction-failed]`). The JSON walk is iterative: deep input cannot overflow the stack. In the
  full tier a failing scan gives `[REDACTED:error]` (no fallback) for the text or the JSON leaf.
- `compat`: reproduces the behaviour of the TypeScript package's default mode for its sync entry (a string under a skip key is
  returned unscanned; keys do not count against `max_chars`; a node-exhausted object keeps its raw key at the
  cut). Use it only to compare with TypeScript output. In the full tier `compat` is TypeScript's async
  behaviour: it has no length, depth or node limit, so giving `max_chars`, `max_depth` or `max_nodes` with
  it raises `ValueError`, and
  a failure of the full-tier rules falls back to the standard rules (and to `[REDACTED:error]` if those fail
  too).

## Limits

| limit | default | meaning |
|---|---|---|
| `max_chars` | 4,000,000 | UTF-16 units: per text, or in total across a JSON value (keys count in `strict`) |
| `max_depth` | 64 | container nesting; a deeper container becomes `[REDACTED:depth-limit]` |
| `max_nodes` | 500,000 | values visited; the rest of the container becomes `[REDACTED:size-limit]` |

All lengths, offsets and windows count **UTF-16 code units** (an astral character is two units, a lone
surrogate one), because the spec fixes that unit for every language. A number that is not replaced comes back
exactly as given (an integer beyond 2^53 is not rounded; the TypeScript package rounds it to a double, so
outputs agree at the double level). A float that is not finite becomes `[REDACTED:redaction-failed]`.

## Not supported

- `restoreRedacted` (restoring values behind placeholders): TypeScript only.

## Development

```sh
cd python
uv sync                     # installs the dev dependency (pytest)
uv run pytest -q            # vectors, golden replay, unicode, strict mode, integrity, metadata, scaling
scripts/wheel-test.sh       # builds the wheel and runs the vectors against the installed wheel
```

The embedded spec lives in `src/droidrun_redaction/spec/` and its hash in `_spec_hash.py`; both are generated
by `tools/sync-spec` from `spec/` (run `tools/sync-spec` after a spec change, `tools/sync-spec --check` in CI).
The scaling test needs [bun](https://bun.sh) to generate the attack strings from `tools/lib/attacks.ts`.
