# secretlint preset inventory

Classification of every rule of `@secretlint/secretlint-rule-preset-recommend` **13.0.4**
(28 rules, in preset order) and the outcome of the port of the full tier into the spec
(decided and done 2026-11-18, see *Port outcome* below). The classification columns are the
input of that port; the rule data is `spec/rules.json` `full`, the algorithms are SPEC.md 4.11
to 4.17.

- **portable-regex**: the rule is one pattern in the portable grammar (SPEC.md section 2),
  plus at most literal allow-list entries.
- **named-algorithm**: needs a named algorithm in SPEC.md, implemented in every language. The
  *needs* column names the element that the grammar cannot say.
- **not-portable**: cannot or must not be ported; stays out of the spec and needs a decision.

How the package runs the rules: `engine.ts` hands every rule `filePath: message.txt`,
`ext: .txt`, content type `text`, and turns on AWS ID scanning (`enableIDScanRule`).
`filter-comments` is left out of the list. So some branches of a rule can never fire here;
the column *in this package* says what is live.

**letter-guard** = the lookbehind `(?<!\p{L})`: a match counts only when the character before it
is not a Unicode letter. Exact parity needs the Unicode General Category L, so the algorithm
has to pin one Unicode version in all three languages (an ASCII-only guard would find
`éghp_…`, which the upstream rule does not; verified). It is one algorithm shared by 20 rules.

| # | rule id | what it matches | class | needs | in this package |
|---|---|---|---|---|---|
| 1 | aws | Access Key ID (`AKIA`, `ASIA`, `A3T?`, `AGPA`, `AIDA`, `AROA`, `AIPA`, `ANPA`, `ANVA` + 16), account id with a key name, `AWS_SECRET_ACCESS_KEY = <40>` | portable-regex | explicit `\s`; two built-in allow-list literals; **range quirk**: the secret-key hit is `[match start, match start + 40]`, i.e. it begins at the key name and ends 40 characters later, not at the secret | live (ID scan on) |
| 2 | gcp | service-account JSON (`JSON.parse`, `private_key_id` + PEM `private_key`) and `.p12` files (PKCS#12 MAC check with the password `notasecret`) | not-portable | JSON parse of the whole content, file system read, Web Crypto | inert: only for `.json` / `.p12` extensions; out of scope, decided by Lutz 2026-11-18 |
| 3 | privatekey | PEM private key blocks, body 100 to 10000 base64 characters | named-algorithm | body bound above 1000; body validation (strip whitespace and `\n`, base64 shape, length at least 100, starts with `MI` or `b3BlbnNzaC1rZXktdjE`) | live |
| 4 | npm | `npm_` + 36 token; `x-oauth-basic@github.com` URL; `_authToken=` in `.npmrc` | named-algorithm | letter-guard | only the `npm_` token is live; the other two need a `package.json` / `.npmrc` file path |
| 5 | basicauth | `http(s)`/`ftp(s)` URL with `user:password@host` | named-algorithm | named groups; back-reference `^(.)\1{3,}$` (repeated character); substring placeholder list; variable-shape tests (`${x}`, `{{x}}`, `%X%`, `$X`) | live |
| 6 | slack | tokens `xoxb`/`xoxp`/`xapp`/`xoxa`/`xoxo`/`xoxr` with dash-separated segments; incoming webhook URLs | named-algorithm | repeated group `(?:[a-zA-Z0-9]{1,40}-)+` (nested quantifier); webhook part is portable (`i` flag written out) | live |
| 7 | sendgrid | `SG.<id>.<secret>`, 69 characters | named-algorithm | letter-guard; exact-length filter on the greedy match | live |
| 8 | shopify | `shppa`/`shpca`/`shpat`/`shpss` + 32 to 64 | named-algorithm | letter-guard; trailing negative lookahead | live |
| 9 | stripe | `sk_live`/`sk_test`/`rk_live`/`rk_test` + 24 to 99 | named-algorithm | letter-guard; trailing negative lookahead | live |
| 10 | github | classic `gh[pousr]_` + 36; fine-grained `github_pat_` + 82; app installation token `ghs_<digits>_<seg>.<seg>.<seg>` | named-algorithm | letter-guard; trailing lookahead; middle segment bound 10000 (above 1000) | live |
| 11 | gitlab | `glpat-` + 20 to 128 | named-algorithm | letter-guard; trailing negative lookahead | live |
| 12 | grafana | `glc_` cloud token (32 to 400 + `=` padding), `glsa_` service account token | named-algorithm | letter-guard; trailing negative lookahead after optional padding | live |
| 13 | openai | `sk-` project/service/admin keys and legacy keys, both containing `T3BlbkFJ` | portable-regex | fixed bounds only; `\b` as a class check | live |
| 14 | anthropic | `sk-ant-api0N-` + 90 to 128 + `AA` | named-algorithm | letter-guard; the body class overlaps the trailing guard, so the match is the maximal run that ends in `AA` | live |
| 15 | groq | `gsk_` + 52 | named-algorithm | letter-guard; trailing negative lookahead | live |
| 16 | huggingface | `hf_` + 34 letters | named-algorithm | letter-guard; trailing negative lookahead | live |
| 17 | linear | `lin_api_` + 32 to 128 | named-algorithm | letter-guard; trailing negative lookahead | live |
| 18 | notion | `ntn_` + 11 digits + 35 | named-algorithm | letter-guard; trailing negative lookahead | live |
| 19 | 1password | `ops_ey…fQ` service-account token whose base64 decodes to a JSON object | named-algorithm | letter-guard; base64 decode (`-`/`_` mapped, binary-string semantics of `atob`) and a JSON parse that must give a non-null object; decode as Latin-1 so invalid UTF-8 cannot differ between languages | live |
| 20 | database-connection-string | MongoDB, MySQL and PostgreSQL URIs with `user:password@` | named-algorithm | named groups; back-reference (repeated character); exact placeholder list; variable-shape tests; `i` flag written out; optional groups | live |
| 21 | hashicorp-vault | `hvs.` / `hvb.` / `hvr.` tokens | named-algorithm | letter-guard; trailing negative lookahead | live |
| 22 | vercel | `vcp`/`vci`/`vca`/`vcr`/`vck` + 20 to 60 | named-algorithm | letter-guard; trailing negative lookahead | live |
| 23 | databricks | `dapi` + 32 hex, optional `-N` | named-algorithm | letter-guard; trailing negative lookahead | live |
| 24 | docker | `dckr_pat_` + 27 | named-algorithm | letter-guard; trailing negative lookahead | live |
| 25 | figma | `figd_` + 40 to 200 | named-algorithm | letter-guard; trailing negative lookahead | live |
| 26 | cloudflare | `cfk`/`cfut`/`cfat` + 40 + 8 hex | named-algorithm | letter-guard; trailing negative lookahead | live |
| 27 | tailscale | `tskey-<type>-<8..40>-<16..60>` | named-algorithm | letter-guard; trailing negative lookahead | live |
| 28 | filter-comments | `secretlint-disable` / `-enable` comments that switch rules off | not-portable | suppression feature: it lets text switch detection off | excluded on purpose (TypeScript engine configuration, `ts/src/rules/index.ts`); must stay absent; decided by Lutz 2026-11-18 |

## Counts

| class | rules |
|---|---|
| portable-regex | 2 (aws, openai) |
| named-algorithm | 24 |
| not-portable | 2 (gcp, filter-comments) |

Of the 24 named-algorithm rules, 15 need nothing but the letter-guard and the trailing
negative lookahead, which the spec grammar already has as `notAfter`: shopify, stripe, gitlab, grafana, groq, huggingface, linear, notion, hashicorp-vault, vercel, databricks, docker, figma, cloudflare, tailscale. The distinct algorithms to specify are
therefore few: letter-guard, base64-JSON check (1password), PEM body validation (privatekey),
URL-credential heuristics (basicauth, database-connection-string), segmented token (slack),
exact-length filter (sendgrid), run with literal tail (anthropic), long middle segment (github app token).

## Decisions

Decided by Lutz, 2026-11-18:

1. **gcp**: stays out (needs `JSON.parse` of the whole content, file access and crypto; the branches are
   inert here anyway). Accepted.
2. **filter-comments**: stays out by design. Accepted.

Decided by Lutz, 2026-11-18 (S4):

3. **letter-guard**: a fixed Unicode 15.0.0 letter table (Lu, Ll, Lt, Lm, Lo) generated into the
   spec (`algorithms.json` `letters`, `tools/gen-letters.ts`), never the runtime's `\p{L}` (SPEC 5.6).
4. **aws range quirk**: the ported rule reports the whole secret value, not
   `[match start, match start + 40]`; the one documented deviation from the preset (SPEC 4.17).
5. The rules not ported stay listed here; nothing is dropped silently.

## Port outcome

All 26 rules other than `gcp` and `filter-comments` are `full`-tier rules in `spec/rules.json`
(rule ids unchanged), checked by an exact (rule id, range) parity test against `@secretlint/core`
13.0.4 (`ts/src/secretlint-parity.test.ts`; the upstream fixtures are in
`spec/corpus/secretlint-13.0.4/`). Ported 2026-11-18:

| rule | kind in `full` | note |
|---|---|---|
| aws | `regex` x3 (key id, account id, secret access key) | key id: example value ignored; secret: range is the secret (L-K) |
| gcp | not ported | decided by Lutz 2026-11-18 |
| privatekey | `pem-key` | 4.14 |
| npm | `token` | only the `npm_` token; the `x-oauth-basic` URL and `_authToken` branches need a `package.json` / `.npmrc` file name the package never gives (inert upstream here) |
| basicauth | `credential-uri` | 4.15 |
| slack | `dash-chain` (token), `regex` (webhook) | 4.12 |
| sendgrid | `sendgrid-key` | 4.13 |
| shopify, stripe, gitlab, huggingface, linear, notion, groq, vercel, docker, figma, cloudflare, tailscale, npm | `token` | 4.11 |
| github | `token` x3 | classic, fine-grained, app installation token (long middle segment) |
| grafana | `token` x2 | cloud token (padding run), service account token |
| hashicorp-vault | `token` x3 | service, batch, recovery |
| databricks | `token` | optional `-N` suffix tried first, guard decides |
| openai | `regex` | |
| anthropic | `token` | run with literal tail `AA` |
| 1password | `token` with `check: base64-json` | 5.7 |
| database-connection-string | `credential-uri` x3 | MongoDB, MySQL, PostgreSQL |
| filter-comments | not ported (by design) | decided by Lutz 2026-11-18 |
