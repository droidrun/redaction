# Redaction spec

Normative description of what `droidrun/redaction` detects and how it rewrites text and JSON
values. The TypeScript package (`ts/`) implements it; Python and Go implement the same spec and
must give byte-identical output. The data lives next to this file (`rules.json`, `keys.json`,
`algorithms.json`); this document defines how to read it and every algorithm the data cannot
express. A Python or Go developer can implement the standard tier from this file and the
vectors alone, without reading the TypeScript.

Words in capitals (MUST, MUST NOT, MAY) are used in the RFC 2119 sense.

Contents: 1 Scope and units, 2 Portable grammar, 3 Spec files and macros, 4 Detection (4.1 to 4.10 standard
tier, 4.11 to 4.17 full tier, 4.18 to 4.22 strict pairs and the `pii` group), 5 Shared algorithms, 6 Key names, 7 Placeholders, hits and splicing, 8 JSON
contract, 9 Tiers and modes, 10 ReDoS rules, 11 Metadata, 12 Spec integrity, 13 TypeScript extensions,
14 Conformance vectors, 15 Known portability risks.

## 1. Scope and units

A **text** is a sequence of UTF-16 code units. The **normative unit is the UTF-16 code unit**,
because the TypeScript implementation counts, slices and reports offsets in code units and its
output is the reference. Everything below that mentions a length, offset, window, cap or bound
counts code units.

- An astral character (U+10000 and above) is two units, a high surrogate then a low surrogate.
- A lone surrogate is a unit like any other. It is allowed in input and MUST be copied to the
  output unchanged when it is not inside a redacted range.
- Python strings are sequences of code points. An implementation MUST convert the input so that
  each code unit is one character (`chr(unit)` per unit; Python allows lone surrogates in `str`)
  before matching and counting, and convert back for output. Offsets are unit offsets.
- Go strings are UTF-8. An implementation MUST decode the input into code units, treating each
  byte sequence that is not valid UTF-8 as one U+FFFD (it is never skipped, so an invalid
  sequence still counts as one unit and can be redacted around). Matching over code units is
  done by mapping every unit in D800 to DFFF to a character that no pattern of the spec mentions
  (for example U+F0000 + (unit minus D800)); every pattern class is either an explicit list of
  BMP characters or a negated list, so any injective mapping of surrogate units to unlisted
  characters gives the same matches. Offsets are unit offsets. An implementation MAY search a slice of
  the text only when no pattern can observe context outside the slice. With the anchor-free grammar of
  section 2 the only context-sensitive token is the word boundary `\b` (the linter bans `^`, `$`, `\B`,
  `\A`, `\Z`, `\G` and lookaround), so a search of a slice MUST give `\b` the real neighbouring character
  of the whole text at both slice edges (Go does this); the simple way is to search the whole text with
  offsets.
- Output is the input with ranges replaced (section 7). Characters outside the ranges are copied
  exactly.

**Hit**: `(ruleId, start, end)`, a half-open unit range with `0 <= start <= end <= length`.

## 2. Portable grammar

Every pattern in `rules.json` and `algorithms.json` is written in the grammar below. It is the
intersection of JavaScript (no flags but the scanning flags), Python `re` with `re.ASCII`, and Go
`regexp` (RE2), so that one pattern string has the same meaning in all three. `tools/lint-spec`
enforces it.

Allowed: literals; a backslash before any ASCII punctuation character or the space (the linter's
list: `\ [ ] ( ) { } . * + ? | ^ $ - / " ' : < > = ! , ; # & % @ ~` and the backtick, `_`, space);
the word boundary `\b`; explicit classes `[...]` and negated
classes `[^...]` that list characters or ranges; alternation `|`; groups `(...)` (capturing) and
`(?:...)`; the quantifiers `* + ?` and `{n}`, `{n,}`, `{n,m}`; the lazy form `?` only on a
bounded quantifier with maximum at most 64.

Banned:

| construct | why |
|---|---|
| `\s \S \w \W \d \D` | their sets differ per engine; write the class out. The JS `\s` set is the macro `WS` (section 3) |
| `.` | differs on line terminators; write the class |
| flags `i`, `m`, `s`, `u`, `v`, inline flags `(?i)` | case folding and anchors differ; write both cases (`[aA]`) |
| `^`, `$` | anchors differ with multiline; the engine searches, it never anchors a rule |
| lookahead `(?=` `(?!`, lookbehind `(?<=` `(?<!` | not in RE2; the rule kinds of section 4 say what they need instead |
| back-references `\1`, `\k<n>`, named groups `(?<n>` | not in RE2 |
| `\n \t \u{...} \p{...} \x..` and other escapes | differ; put the literal character in the class |
| repeat bound above 1000 | RE2 limit; a longer window is a named algorithm |
| possessive quantifiers, atomic groups | not portable |
| unbounded lazy quantifier, lazy bound above 64 | cost and portability |
| a repeated group that holds a repeating quantifier (nested quantifier) | ReDoS |
| a class that starts with `]` (`[]a]`, `[^]a]`) | JavaScript reads `[]` as an empty class, Python and Go read `]` as a member |
| a surrogate unit (an astral character or a lone surrogate) in pattern text | one character in Python and Go, two units in JavaScript |
| a pattern that can match the empty string (a zero-length match on `''`, `'a'` or `' '`) | engines differ and scanners loop |
| a class field that is not exactly one class | ReDoS and engine differences hide in a "class" field |
| rule id outside `^[a-z0-9-]+$` | ids are part of the placeholder |

The linter checks **every** regex-bearing field of a rule, found by name: `pattern`, `header`, `footer`,
`prefix`, `bearer`, `scheme`, `label`, `queryKey`, `bearerAlso` and the list `variablePatterns` hold patterns; `notBefore`,
`notAfter` and every field ending in `Class`, `Char`, `Stop` or `End` (`afterGapClass`, `digitClass`, `identChar`, ...)
hold exactly one character class; `id`,
`kind`, `lead`, `leads`, `separator`, `footerMarker`, `requireLiteral`, `lit`, `alt`, `tails`, `magic`,
`ignoreEquals`, `userIgnoreContains`, `passwordIgnoreContains`, `passwordIgnoreEquals`, `stripLiteral`,
`newline`, `dash`, `underscore`, `check`, `plainWords`, `queryOnlyKeys`, `mode`, `ignoreSuffixes`, `ignoreAfterWords`,
`statusWords`, `schemeWords`, `schemeKeys` are literal text. The check looks into
nested objects and lists (the `parts` of a token). A string field with another name is an error, so a new field
cannot escape the checks.

A pattern is searched, never anchored: matches are found left to right, each starting at the
leftmost position where the pattern matches, with the preference order of Perl-style engines
(leftmost-first: alternatives and greedy/lazy quantifiers prefer in the order written). Scanning
resumes at the end of an accepted match. JavaScript, Python and Go agree on this for the grammar
above. Python compiles every pattern with `re.ASCII` at runtime too (so `\b` is the ASCII word
boundary: word characters are `A-Z a-z 0-9 _`), JavaScript without `u`, Go as is; `\b` has the
same meaning in all three.

Case-insensitive words are written with both cases explicitly. The spec generates them from a
word list (the word macros of section 3), so nobody writes `[pP][aA][sS][sS]` by hand.

A rule that has to look at its neighbours does not use lookaround. It uses the guard fields of the
rule kind in section 4 (`notBefore`, `notAfter`), which are defined as code, not as pattern text.

## 3. Spec files and macros

All three data files carry `"specVersion": 1`. An implementation that sees another version MUST
refuse to load. `spec/schema/*.schema.json` are JSON Schemas for the files.

`rules.json`:

- `macros`: named text snippets. A macro is a string, or a **word macro**
  `{ "join": J, "words": [[w, ...], ...] }` (or `"fromKeys": "secretWords"` instead of `words`,
  which takes the word lists of `keys.json`).
- `patterns.placeholder`: the placeholder grammar (section 7).
- `pipeline`: the ordered rule list of the standard tier in `compat` mode (sections 4.1 to 4.10); it is the v0.2.0
  contract and holds no rule of `strict` or `pii`.
- `strict`: the edits that turn the `pipeline` into the rule list of `strict` mode, a list of objects (section 4.10).
- `pii`: the ordered rules of the opt-in `pii` group (sections 4.19 to 4.22).
- `full`: the ordered rule list of the full tier, the ported secretlint preset (sections 4.11 to 4.17).

**Expansion.** Every string that is a pattern or a class is expanded before use: each `{{NAME}}`
is replaced by the macro `NAME`, repeatedly until nothing changes (nesting depth at most 8; more
is an error, an unknown name is an error). A string macro is inserted as is. A word macro is
inserted as `(?:` alternatives joined by `|` `)`; one alternative is its words joined by `J`
(J is pattern text, for example `[_-]?`); inside a word every ASCII lower-case letter `x` is
written `[xX]`, every other character as it is. The order of the alternatives is the order of the
list.

The macro `HSPACE` is `WS` without the four line terminators (U+000A, U+000D, U+2028, U+2029): spaces that do not
start a new line.

The macro `WS` is the exact JavaScript `\s` set written out, as characters (not escapes): U+0009,
U+000A, U+000B, U+000C, U+000D, U+0020, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F,
U+205F, U+3000, U+FEFF. It is used inside classes as `[{{WS}}]` or `[^{{WS}}...]`. Nothing else is
whitespace anywhere in the spec: **trim** removes characters of this set from both ends of a
string.

**Lower-casing** in the spec (`lower`) maps `A` to `Z` to `a` to `z` and U+212A (KELVIN SIGN) to
`k`, and changes nothing else. Every comparison of words and every `lower(x) ==` test below uses
it (JavaScript `toLowerCase` gives the same result on every string such a comparison can match).

`keys.json` (section 6) and `algorithms.json` hold word lists and numeric parameters (and the letter table
of section 5.6); they are named where they are used.

## 4. Detection

Sections 4.1 to 4.10 and 4.18 are the standard tier (4.18 only in `strict`), 4.11 to 4.17 the full tier, 4.19 to
4.22 the opt-in `pii` group. `detect(text, mode, pii)` returns the merged hits of the standard tier, with `mode` (`compat` or `strict`,
section 9) and `pii` (boolean, default false, section 9.5).

1. Let `hits` be empty. For each rule of the rule list of `mode` (4.10) in order, then, when `pii` is true, for each rule
   of `pii` in order, run the rule kind below on the whole text. It returns ranges in the order given by its kind.
   Append `(rule.id, start, end)` for each range to `hits`. Several entries may share an id.
2. Return `merge(hits)` (section 7).

In `compat` without `pii` the rules never see a text shorter than `text.minScanLength` (8): `redact` returns it
unchanged (section 9, the v0.2.0 contract). In `strict`, and in any mode with `pii`, a text of any length is scanned
(`dr_sk_a`, `token=x`, `a@b.xx`). A range returned by a rule has `start <= end`; rules drop empty ranges where noted.

**Placeholder test of a range** `isPlaceholderValue(text, start, end)`: let `e` be the end of the
placeholder (section 7) that starts exactly at `start`, or none; true when `e` exists and `e >= end`.
This is the idempotence guard: a value that already is (the start of) one of our placeholders is
never redacted again.

Rule kinds. `P` is the expanded pattern text; `scan(P)` is the global search of section 2.

### 4.1 `regex`

Fields: `pattern`, optional `group` (default 0), `notBefore`, `notAfter`, `requireClass`,
`requireLiteral`, `dropPlaceholder`, `ignoreEquals`, `ignoreSuffixes`, `ignoreAfterWords` with `afterGapClass`,
`ignoreBeforeClass`, `ignoreAfterClass`, `check` with `minColons`.

1. Find matches of `pattern` left to right. The candidate range is the whole match, or the span of
   capture group `group`.
2. **Guards** (only when `notBefore` or `notAfter` is present; they are allowed only on a pattern
   of fixed match length, so that resuming one unit later is exact). For a match `[s, e)`: it is
   refused when `s > 0` and the unit `text[s-1]` is in the class `notBefore`, or when `e < length`
   and `text[e]` is in the class `notAfter`. A refused match restarts the search at `s + 1`. An
   accepted match restarts at `e`.
3. **Filters** on the candidate, all that are present: `requireClass`: the candidate text contains
   a unit of the class; `requireLiteral`: it contains the literal; `dropPlaceholder`: it is not an
   `isPlaceholderValue`; `ignoreEquals`: its text is not equal to one of the listed strings (exact, case
   sensitive); `ignoreSuffixes`: `lower(candidate)` does not end with one of the listed literals (the file
   extensions after the host of an email); `ignoreAfterWords`: the **word before the match** (below) is not one of
   the listed words; `ignoreBeforeClass` / `ignoreAfterClass`: the unit before the **whole match** is not in the class,
   and the unit after it is not in the class (the match is not a piece of something longer; unlike `notBefore` and
   `notAfter` they apply to a pattern of any length, and a dropped match is consumed); `check`: the named check of 5.8 accepts the candidate (`minColons` is its argument). An unknown
   `check` name stops the package at load time. A candidate that fails a filter is dropped (the search is not
   restarted: the match was consumed).

   **Word before the match.** Let `s` be the start of the **whole match** (not of the group), `g` be `s` minus
   the length of the maximal run of units of `afterGapClass` (none when the field is absent) that ends at `s`, and
   the word be the maximal run of ASCII letters `A-Z a-z` that ends at `g`, lower-cased (`lower`, section 3). It is
   empty when no letter stands there. (`version 1.2.3.4`: the word before `1` is `version`.)
4. Output the surviving candidates in order.

**A `regex` rule has either a capture `group` or guards, never both.** The guarded path reports whole matches
(it restarts one unit after a refused match, which is exact only for a fixed-length whole match), so a group
there is ambiguous; `tools/lint-spec` rejects the combination.

A match of `group` where the capture group **did not participate** in the match (it is in an alternative
that was not taken) has no span: the match is dropped, nothing is output for it. A rule pattern never matches
the empty string (the linter rejects such patterns), so the empty-match case does not arise; if an engine
reports an empty match anyway, the search position advances by one unit before the next search (the
ECMAScript `matchAll` rule).

### 4.2 `dotted-token`

Fields: `lead` (`eyJ`), `separator`, `segmentClass`, `wordClass`, `minSegment`, `segments`.
This is the JSON Web Token shape. It is the same as the (non-portable-bound, quadratic)
expression `\b lead SEG{min,} (separator SEG{min,}){segments-1} \b` but linear.

Let `isWord` be `wordClass` and `boundary(i)` be true when exactly one of `text[i-1]`, `text[i]`
is a word unit (outside the text counts as not a word unit).

1. Candidate starts are the positions of `lead` in increasing order, except those below `skipUntil`
   (initially 0) and those where `boundary(start)` is false.
2. At a start, let `p = start + length(lead)`. For segment number 1 to `segments`: let `run` be the
   maximal run of `segmentClass` units from `p`, `L` its length. If `L < minSegment`, the start
   fails. For every segment but the last: the unit after the run MUST be `separator`, else the
   start fails; set `p` to just after it. For the last segment: take the largest `t` with
   `minSegment <= t <= L` such that `boundary(p + t)` holds; none: the start fails. The match is
   `[start, p + t)`.
3. A failing start sets `skipUntil` to the end of the first segment's run (no other start inside
   that run can succeed). A match is output, and the next search position is its end.

### 4.3 `pem-blocks`

Fields: `header`, `footer`, `footerMarker`, `bodyChar`, `bodyLimit`.

1. Find all matches of `header` first (left to right, non-overlapping). Let `covered = 0`.
2. For each header match `[s, b)` in order: skip it if `s < covered`. Let `limit = min(length, b +
   bodyLimit)`. Let `bodyEnd` be the first index in `[b, limit)` whose unit is not in `bodyChar`,
   or `limit`. Let `f` be the first index `i` in `[b, bodyEnd)` where the literal `footerMarker` starts
   (the marker may run past `bodyEnd`, but it must **start** before it). If `f` exists and `footer`
   matches exactly at `f` (anchored there), then `covered = ` end of that match; otherwise
   `covered = bodyEnd`.
3. Output `[s, covered)`.

**The footer search is bounded**: it looks only at starts in `[b, bodyEnd)`, never to the end of the text. A
search to the end of the text finds the same `f` whenever one counts, but costs time proportional to the whole
remaining text per header, which is quadratic on `-----BEGIN PRIVATE KEY-----!` repeated. With the bound, the
windows of successive headers overlap by less than the marker length (the next header starts at or after
`covered >= bodyEnd`), so the rule is linear. An implementation MAY additionally cache the next marker
position, but the bound is what the spec requires.

An unterminated block is therefore redacted through the end of its body-looking run (fail
closed). The body class includes `\`, so keys written with literal `\n` in JSON text are covered.

### 4.4 `cookie-lines`

Fields: `prefix`, `plainChar`, `escapeStop`, optional `requireLiteral`, `dropPlaceholder`.

For each match of `prefix` (found with the search of section 2): the value starts at the end of the
match, `v`. Its end is `runEnd(v)` of the **guarded run** (section 5.1) with `plainChar` and
`escapeStop`, unbounded. If the run is empty, the search restarts at `matchStart + 1` and nothing
is output. Otherwise the search restarts at the run end, and the range `[v, runEnd)` is output when
it passes the filters of 4.1 step 3.

### 4.5 `auth-values`

Fields: `bearer`, optional `bearerAlso`, `scheme`, `valueClass`, `minValueLength`, `lowerClass`, `upperClass`,
`wordClass`, `plainWords`.

The rule output is all Bearer ranges in text order, then all scheme ranges in text order, with
both filtered by step 3.

1. **Bearer**: for each match of `bearer`, the range of capture group 1; then the same for `bearerAlso` when the rule
   has it (a second search of its own, so that a wider pattern never consumes what the first would find; the ranges
   of both are output).
2. **Scheme** (`Basic` / `Token`, also ordinary words): for each match of `scheme` (it ends after
   the whitespace): `v` is the match end; `end` is the end of the maximal run of `valueClass` from
   `v`. Reject when any of: `end - v < minValueLength`; **plain word**: the maximal run of
   `lowerClass` from `v` is non-empty and its end is followed by a non-word unit or the text end
   (`wordClass` units are word units); **Capitalized word**: `text[v]` is in `upperClass`, the
   maximal run of `lowerClass` from `v + 1` is non-empty, and its end is followed by a non-word
   unit or the text end. A rejected match restarts the search at `matchStart + 1`. An accepted one
   outputs `[v, end)` and restarts at `end`.
3. **Filter**: drop a range when `lower(text[start..end])` is in `plainWords` ("Missing or invalid
   bearer token" is prose), or when it is an `isPlaceholderValue`.

### 4.6 `keyword-pairs`

Fields: `prefix`, `plainChar`, `escapeStop`, `minValueLength`, `window`, `identChar`,
`labelLookback`. The generic keyword rule: a credential keyword anywhere in an identifier
(`session_token:`, `clientSecret=`), a separator, then a value that has evidence of being
secret. The `prefix` pattern holds the keyword, up to 64 identifier units, an optional quote
(escaped any number of times) and the separator.

Scan `prefix` from position 0. For each match `m` (start `ms`, end `v`):

1. `valueEnd = guardedRunEnd(v)` with `plainChar` / `escapeStop`, at most `window` (256) units. If
   `valueEnd - v < minValueLength` (8): restart the search at `ms + 1`; no range.
2. `label = labelStart(ms)` (5.2). `[start, end) = trimQueryValue(label, [v, valueEnd))` (5.3).
3. The candidate is **accepted** when `end > start`, it is not an `isPlaceholderValue(start, end)`, and
   `hasValueEvidence(text[start..end])` (5.4).
4. Not accepted: restart the search at `v` (the start of the rejected value, so a value that is itself a
   label still starts its own pair; this keeps `a_token=a_token=...` linear).
5. Accepted: if `end - start == window` the value filled the capture window and is **extended**: the
   end becomes `guardedRunEnd(end)` unbounded (done only now, so a rejected candidate never rescans
   its run; no suffix of a long secret is left behind). Output `[start, end)` and restart the search
   at `max(end, v)`.

### 4.7 `quoted-pairs`

Fields: `label` (ends at the opening quote; capture 1 = the escape backslashes before the quote,
capture 2 = the quote character), `valueLimit` (1024).

For each match of `label` (restart at the end of the previous accepted value, below): `from` is the
match end, `layers` the length of capture 1, `quote` capture 2, `limit = min(length, from +
valueLimit)`.

1. **Closing quote**: for `i` from `from` to `limit - 1`: if `text[i] != quote` continue. Let `run` be the
   number of consecutive `\` units immediately before `i` (not going before `from`). The quote
   closes the value when (`layers == 0` and `run` is even) or (`layers > 0` and `run == layers`).
   The value then ends at `i - run`. The first such `i` wins.
2. No closing quote found: the value is `[from, length)` (an unterminated or over-long quoted value
   fails closed: redacted to the end of the text), it is collected, and the scan of this rule
   **stops**.
3. Otherwise collect `[from, i - run)` and restart the search at `i - run`.
4. After the scan, drop collected values that are empty, an `isPlaceholderValue`, a trivial value
   (5.5) or a documentation stand-in (5.5).

### 4.8 `unquoted-pairs`

Fields: `prefix`, `plainChar`, `escapeStop`. For each match of `prefix`: `v` the match end,
`end = guardedRunEnd(v)` unbounded. Empty run: restart at `matchStart + 1`, nothing collected.
Otherwise restart at `end` and collect `trimQueryValue(matchStart, [v, end))`. After the scan, drop
values as in 4.7 step 4.

### 4.9 `query-values`

Fields: `queryKey` (a pattern with capture 1 = the parameter name; it starts at `?` or `&`),
`queryOnlyKeys`, `valueEnd`, `nestedEnd`, `nestedLimit` (4096), `decodeBudget` (1,000,000),
`dropPlaceholder`. Redacts the values of secret-named URL query parameters.

`isSecretParam(k)` is `isSecretKeyName(k)` (section 6) or `lower(k)` in `queryOnlyKeys` (`code`,
`sid`, `session`, `otp`, `pwd` are ordinary words in JSON, secret only in a URL query).

`percentDecode(x)` is ECMAScript `decodeURIComponent`, except that it never fails: on a malformed
sequence it returns `x` itself, unchanged and whole (never a partial decoding). Exact steps, over the units
of `x`:

1. Walk `x` left to right. A unit other than `%` is copied. (`+` is copied: it is **not** a space.)
2. A `%` must be followed by two hexadecimal digits (`0-9 a-f A-F`), else `x` is malformed. Let `b` be the
   byte they give.
3. If `b < 0x80` the byte is the character `b`. Otherwise it is the first byte of a UTF-8 sequence: count its
   leading one bits `k`; `k == 1` or `k > 4` is malformed. The next `k - 1` units MUST each be `%` and two hex
   digits giving a byte of the form `10xxxxxx`, else malformed. Compute the code point from the bits. It is
   malformed when it is overlong (below `0x80`, `0x800`, `0x10000` for `k` = 2, 3, 4), when it is in
   `0xD800` to `0xDFFF`, or above `0x10FFFF`.
4. The result is the text of the copied units and decoded characters; an astral character is two UTF-16 units
   (every later step, including `hasSecretQueryParam`, works on units).

Not conforming: Python `urllib.parse.unquote` (it replaces errors with U+FFFD and decodes the rest) and Go
`url.QueryUnescape` (it turns `+` into a space). Python: decode the byte runs with a strict UTF-8 decoder
(`errors='strict'`), on any error return `x`. Go: implement the steps above (`url.PathUnescape` neither
validates the UTF-8 nor rejects the same sequences).

`budget = decodeBudget`. Scan `queryKey` from 0. For each match: `v` is the match end, `key =
percentDecode(capture 1)`.

1. `isSecretParam(key)`: `end` = first index `>= v` whose unit is in `valueEnd` (or the length); if `end > v`
   output `[v, end)`. Restart the search at `max(v, end)`.
2. Otherwise, if `budget <= 0` continue (restart at `v`, the normal continuation). Else the nested
   value is the units from `v` up to the first unit in `nestedEnd`, at most `nestedLimit`; call its
   end `e`. `budget -= e - v`. `raw = text[v..e)`. If `raw` has no `%`, continue. `decoded =
   percentDecode(raw)`. If `decoded != raw` and `hasSecretQueryParam('?' + decoded)` then output `[v, e)`.
   Restart at `v`.
3. `hasSecretQueryParam(s)`: scan `queryKey` over `s`; true when any match has `isSecretParam
   (percentDecode(capture 1))`.

After the scan drop ranges that are empty or an `isPlaceholderValue` (`dropPlaceholder`).

### 4.10 Rule order of the standard tier

`rules.json` lists the pipeline in this order, and the order is normative because equal-start hits
keep the first rule's id (section 7): `jwt`, `gcp-api-key`, `xai-api-key`, `platform-token`,
`platform-key`, `github`, `aws`, `slack`, `stripe`, `private-key`, `openai`, `url-credentials`,
`cookie`, `auth-header`, then `generic-keyword` (keyword pairs, quoted pairs, unquoted pairs in
that order), then `key-context` (query values).

**The rule list of a mode.** The list of `compat` is `pipeline`, with every field as written (the v0.2.0 contract,
section 9). The list of `strict` is built from it by the edits of `rules.json` `strict`, applied in order. An edit is an
object with `id` and/or `kind`: it matches every entry of the list whose `id` and `kind` equal those given (the
list as the earlier edits left it); an edit that matches no entry stops the package at load time, and `tools/lint-spec`
checks it. An edit has `set` (an object whose fields replace the fields of every matched entry) or `add` (a rule
inserted right after the matched entry; the edit must match exactly one entry). There is no edit that removes or
replaces a rule: **strict is a superset of 0.3.0 strict** (section 9).

The edits, in order, and `compat` does none of them:

1. `platform-key` reads `dr_sk_` in any letter case, with any non-empty body and without a word boundary before it
   (`dr_sk_first`, `DR_SK_...`, `x_dr_sk_...`, an escaped `\n` or `%22` before it).
2. `auth-header` gets `bearerAlso`: the whole Bearer credential, every unit up to whitespace or up to a quote (`"`,
   `'`), `<`, `>`, `,`, `;` or `\`, after an optional opening quote (`Bearer abc!defghijklmnop`, `Bearer "abc"`). The
   narrow `bearer` pattern is still searched, so no credential found before is lost. `Basic` and `Token` are unchanged.
3. `keyword-pairs` (prefix), `quoted-pairs` (label) and `unquoted-pairs` (prefix) accept `=>` and `:=` as a separator
   next to `:` and `=`, so `password => "x"` is a pair and `token=>abc` is a fixed point of redaction.
4. The `key-pairs` rule of 4.18 is **added** right after the unquoted pairs.

**Superset.** For every input, the `strict` of this version redacts every range the `strict` of 0.3.0 redacted, with
one narrow exception: where `=>` or `:=` is the separator, 0.3.0 read the `>` or `=` as the first unit of the value, so
it redacted that unit and judged the value with it (`secret:=changeme` gave the range `=changeme`, a stand-in
`changeme` now stays; `bearer:=hunter2` passed the 8-unit test only because of the `=`). The merge (section 7) unions
the hits of the old and the new rules, which is why a new rule is added and an old one is never replaced.

### 4.11 `token` (full tier)

A key format: literals and runs of units of a class, an optional letter guard in front, and a class that must
not follow. It is what the upstream expression `(?<!\p{L})PREFIX[CLASS]{a,b}(?![CLASS2])` means, written without
backtracking. Fields: `parts` (list), optional `letterGuard` (boolean), `notAfter` (a class), `check`
(`base64-json`) and `checkFrom` (a unit offset, default 0).

A part is one of: `{lit}` (a literal); `{alt}` (a list of literals, none a prefix of another; the first that
matches at the position is taken); `{runClass, min, max}` (a run of units of the class, with optional `tails`);
`{opt}` (a list of literals and fixed runs; tried first, then skipped when the rest of the shape fails). The first
part is a `lit` or `alt`.

`scanToken(text)`: for each position `s` where a first literal starts (left to right, each position once):

1. If `letterGuard` and the letter guard (5.6) refuses `s`: go on with `s + 1`.
2. Match the parts in order from `s`, with `p` the current position:
   - `lit` / `alt`: the text at `p` starts with the literal; `p` moves past it.
   - a **fixed run** (`min == max`, no `tails`): the next `min` units are all in the class.
   - a **variable run**: let `end` be the end of the **maximal** run of the class from `p` and `n = end - p`.
     Without `tails`, `min <= n <= max` is required. With `tails`: the first tail (list order) the run ends with
     (the units of the tail are the last units of the run); `n` is then the run length minus the tail length, and
     `min <= n <= max` is required; no such tail fails. `p = end`.
   - `opt`: match its parts from `p`; if that and everything after it succeeds, take it; otherwise continue
     after the `opt` from `p` unchanged.
3. After the last part: if `p < length` and `text[p]` is in `notAfter`, the match fails (for an `opt` this
   makes the shape try again without it).
4. A failed shape goes on with `s + 1`. A match `[s, p)` is dropped when `check` is set and the check fails on
   `text[s + checkFrom .. p)` (the match is still consumed); otherwise it is output. Scanning goes on at `p`.

**Run memory (normative).** The end of a maximal run is measured once and reused: for every variable-run part of a
shape (not for every class: two parts of one class are two memories) an implementation keeps the last run it
measured in the scan (its start and end) and, when a later start asks for a run that begins inside it, answers
with the remembered end instead of walking the run again. Starts only move forward, so the work of one rule over
one text is linear. A memory per class is **not conforming**: the parts of one class overwrite each other, and
`ghs_1_` repeated 170 times, then `.`, then 100,000 `a` measures the long run again at every start (about 2,000
times slower than the memory per part on a 2,000,000-unit text; `tools/lib/attacks.ts` holds this attack for
every shape with repeated run classes). The memory of a part is made when the part first runs in a scan.

The maximal run equals what the backtracking expression finds under conditions that `tools/lint-spec` checks:
what follows a variable run never starts with a unit of the run's class, and a variable run at the end of the
shape (or followed only by runs with `min` 0) needs `notAfter` to contain its class, so every shorter run is
refused. A fixed run has no alternative. The checks are on the rule data, so a new rule cannot break them.

`check` `base64-json` (5.7) is used by the 1Password rule. A `check` name the implementation does not know stops the
package at load time (it is never read as "no check").

### 4.12 `dash-chain` (full tier)

Slack tokens: `\b(?:xoxb|xoxp|xapp|xoxa|xoxo|xoxr)-(?:\d-)?(?:[a-zA-Z0-9]{1,40}-)+[a-zA-Z0-9]{1,40}\b` written
without backtracking. Fields: `leads`, `separator`, `segmentClass`, `wordClass`, `maxSegment` (40), `minSegments`
(2). For each position `s` where a lead starts (left to right):

1. `s` is refused when `text[s - 1]` is a `wordClass` unit (a word boundary is needed in front: the lead starts
   with a word unit). Else go on with `s + 1`.
2. After the lead the text must have `separator`.
3. The **chain**: from the position after it, repeat: `run` is the maximal run of `segmentClass`; stop when its
   length is 0 or above `maxSegment`; otherwise record its end and, when `text[end]` is the separator, go on after
   it, else stop. Let `K` be the number of recorded runs.
4. The token ends at the last run if the unit after that run is not a `wordClass` unit (a word boundary), else at
   the run before it. `used` is the number of runs the token has (`K`, or `K - 1`). If `used < minSegments`
   the start fails (go on with `s + 1`).
5. Output `[s, end of run used)`; scanning goes on at its end.

The optional leading digit of the expression only moves the first run out of the repeated group; it never changes
the match (the same chain, the same end), so it is not part of the data.

### 4.13 `sendgrid-key` (full tier)

SendGrid keys: `(?<!\p{L})SG\.\w{1,128}\.\w{1,128}([-_]?)\w{1,128}(?!\w)` and only a match of exactly 69 units is
a key. The expression backtracks, so *which* match it finds decides what the scan consumes, even when the length
test then drops it. Fields: `lead` (`SG.`), `separator` (`.`), `wordClass`, `dash`, `maxSegment` (128), `length` (69). For each position `s` where `lead` starts:

1. Letter guard (5.6); refused: go on with `s + 1`.
2. `A` = the maximal run of `wordClass` after `lead`; its length is `1..maxSegment` and `text[end of A]` is
   `separator`, else the start fails. `p` = the position after the separator.
3. `R` = the maximal run of `wordClass` from `p`, `r` its length, `E = p + r`. `r == 0` fails. Then, in this order,
   the first that holds gives the end of the match:
   a. `r <= maxSegment`, `text[E]` is `dash`, and the maximal run `C` of `wordClass` after it has length
      `1..maxSegment`: the end is the end of `C`.
   b. `2 <= r <= 2 * maxSegment`: the end is `E`.
   Else the start fails (`s + 1`).
4. The match `[s, end)` is consumed (scanning goes on at `end`) and output only when `end - s == length`.

(These are the matches of the backtracking expression: the two runs after the separator share one run `R` unless
the joiner is the dash, and a dash can only follow a run that is not longer than `maxSegment`. The expression has
one more match, `r == 2 * maxSegment + 1` with `_` as the joiner at offset `maxSegment`; it is left out because it
changes no output: its length is above 69, so it is never a key, and it cannot hide another start, since a start
inside the match needs `SG.` and the match holds a `.` only at its separator.)

### 4.14 `pem-key` (full tier)

The private key rule of the preset: header, body of 100 to 10000 units, footer, and a body that really is the
base64 of a key. Unlike `pem-blocks` (4.3) an unterminated or invalid block is **not** a hit. Fields: `header`,
`footer` (patterns), `bodyClass` (no `-` in it), `minBody`, `maxBody`, `newline` (a line feed), `stripClass`,
`stripLiteral` (the two units `\` and `n`), `contentClass`, `padChar`, `minContent`, `magic`. The header search
resumes at `h + 1` after a failed start (a header may start inside the trailing dashes of the previous one) and
at the footer end after a hit. For each header match `[h0, h)`:

1. `E` = the end of the maximal run of `bodyClass` from `h`, `L = E - h`, `lead` = `text[h]` is `newline`,
   `trail` = `L > 0` and `text[E - 1]` is `newline`.
2. The body length is acceptable when one of `L`, `L - 1` (if `lead`), `L - 1` (if `trail`), `L - 2` (if both,
   `L >= 2`) is in `minBody..maxBody` (the expression may or may not take the line feed after the header and the
   one before the footer into the body).
3. The footer pattern must match **exactly at `E`** (anchored there; the body class has no `-`, so the body ends
   at `E`).
4. `content` = the text `[h, E)` without every unit of `stripClass` and without every occurrence of
   `stripLiteral`, scanned left to right (a unit of the class is removed; else if `stripLiteral` starts here it is
   removed as a whole; else the unit is kept). It is valid when it starts with one or more units of
   `contentClass`, then only `padChar` units, is at least `minContent` long, and starts with one of `magic`.
5. A valid block outputs `[h0, footer end)`.

### 4.15 `credential-uri` (full tier)

URLs that carry `user:password@`, from the basic-auth and database-connection-string rules. Fields: `pattern`
(capture group 1 = user, group 2 = password; every other group is non-capturing), `userMin`, `passwordMin`,
`userIgnoreContains`, `passwordIgnoreContains`, `passwordIgnoreEquals`, `userEqualsPassword`,
`variablePatterns`, `repeatRun`. For each match of `pattern` (left to right, each match consumed whether it is
reported or not), skip it when group 1 or group 2 did not take part or is empty. Otherwise report the **whole
match** when all hold (`lower` is section 3; `contains` is a substring test on the lower-cased texts):

- `length(user) >= userMin` (0 when absent); `lower(user)` contains none of `userIgnoreContains` (lower-cased);
- not (`userEqualsPassword` and `user == password`, case sensitive);
- `length(password) >= passwordMin`;
- no pattern of `variablePatterns` has a match in `password` (a search, anywhere);
- `lower(password)` contains none of `passwordIgnoreContains` and equals none of `passwordIgnoreEquals`;
- `password` is not `repeatRun` or more units that are all the same unit.

(The standard tier already replaces such a password by `[REDACTED:url-credentials]`, which the full tier then reads
as a real password: the output of the standard tier is not a fixed point of the full tier for a URL whose password
the checks reject; the upstream rules behave the same and no vector covers it.) (The basic-auth class of user and password has no `$ { } % ( )`, so the template patterns of the upstream
basic-auth rule can never match there; they are left out of that rule's data.)

### 4.16 Rule order of the full tier

`rules.json` lists `full` in the order of the upstream preset, and the order is normative for ties (below):
`aws` (key id, account id, secret access key), `privatekey`, `npm`, `basicauth`, `slack` (token, webhook),
`sendgrid`, `shopify`, `stripe`, `github` (classic, fine-grained, app installation), `gitlab`, `grafana` (cloud,
service account), `openai`, `anthropic`, `groq`, `huggingface`, `linear`, `notion`, `1password`,
`database-connection-string` (MongoDB, MySQL, PostgreSQL), `hashicorp-vault` (service, batch, recovery),
`vercel`, `databricks`, `docker`, `figma`, `cloudflare`, `tailscale`. Rule ids are the upstream ids without the
`@secretlint/secretlint-rule-` prefix.

### 4.17 Full-tier detection

`detectFull(text)`: run every rule of `full` on the text (the first `full.scanCap` units, 9.4); the hits are
`(rule id, start, end)`, stable-sorted by `start`, then by `end` (equal pairs keep rule order). The full tier's
`detect` is `merge(detectFull(text) ++ detect(text))` (section 7): the full-tier hits come first, so on an equal
start their rule id wins. The AWS secret access key rule reports the 40 units of the secret (`group` 1), not
`[match start, match start + 40]` as the upstream rule does (decided 2026-11-18); this is the only
deviation from the upstream preset, and the parity test names it. Not ported (INVENTORY.md): `gcp`,
`filter-comments`, and the two `npm` branches that need a `package.json` or `.npmrc` file name, which the package
never supplies.

### 4.18 `key-pairs` (strict)

Added to the `strict` list right after the unquoted pairs (4.10): it never replaces them, so what they redact stays
redacted. Fields: `label` (a pattern that starts at the separator `=>`, `:=`, `:` or `=`, followed by spaces that do
not start a new line (macro `HSPACE`) and an optional quote of the value: capture 1 = the escape backslashes before the
opening quote, capture 2 = the opening quote; 1 and 2 take part together or not at all), `valueLimit` (1024),
`plainChar`, `escapeStop`, `identChar`, `labelLookback`, `keyChar`, `keyMax` (64), `gapClass`, `quoteChar`, `digitClass`,
`standInMinLength` (2), `keptMaxLength` (64), `statusWords`, `schemeWords`, `schemeKeys`. The text form of the JSON key
rule of section 6: a pair `key: value` whose key the **same verdict** (`keyVerdict`, section 6) calls secret, so one list
of key names serves JSON keys and text. The key is found by looking back from the separator (step 1), so no pattern scans
an identifier at every start of the text. The kept words, the stand-ins and the number rule below are what lets short
values be redacted without redacting ordinary prose.

Scan `label` from position 0. For each match `m` (start `ms`, end `from`):

1. **Key.** Let `e` be `ms` minus the length of the maximal run of `gapClass` units that ends at `ms`. When the unit before
   `e` is in `quoteChar`, move `e` back over it and then over every `\` unit before it (an escaped quote, any number of
   times). The key is the run of at most `keyMax` units of `keyChar` that ends at `e` (the units nearest to `e`; a longer
   run gives its last `keyMax` units); with an empty run there is no key: no range, the search continues at `from`.
   `verdict = keyVerdict(key)`. When it is `none`: no range; the search continues at `from` (a pair inside the value,
   `a=password=x`, is still found).
2. **Value.** It is **quoted** when capture 2 took part. It ends at the closing quote found as in 4.7 step 1 (`layers` =
   the length of capture 1, `valueLimit`). With no closing quote (unterminated, or longer than `valueLimit`, multi-line
   ones included) it fails closed whatever the value is, a kept word included (`password="Bearer`): the range
   `[from, length)` is output unless it is empty or an `isPlaceholderValue`, and **the scan of this rule stops**. An
   unquoted value is the guarded run (5.1) of `plainChar` / `escapeStop` from `from`, unbounded; since the spaces of
   `label` are `HSPACE`, it never starts after a line break (`secrets:\n  api_key: x` has no value under `secrets`). An
   empty run gives no range and the search restarts at `ms + 1`. The range of an unquoted value is cut at the next `&` when
   its label is inside a URL query (`labelStart` 5.2 from the start of the key, `trimQueryValue` 5.3). **The end of a run
   is the same from every start inside it**, and so is the next `&`, so an implementation measures a run once and
   remembers the next `&` (a text of many pairs inside one long run, such as `?token=` repeated, is then linear); a run measured again at every pair is
   quadratic and not conforming.
3. **Kept.** A value of at most `keptMaxLength` units is **kept** (no range, the search continues at `from`) when it is
   empty, an `isPlaceholderValue`, a **stand-in** (`isTrivialValue` or `isDocPlaceholder`, 5.5; `isTrivialValue` counts
   only for a value of at least `standInMinLength` units, so a single `x` or `*` is a value), a **status word**
   (`lower(trim(value))` is in `statusWords`: `expired`, `required`, `failed`, `missing`, `invalid`, `true`, `false`,
   `null`, `none`), a **scheme word** (in `schemeWords`: `bearer`, `basic`, `digest`) when the key, lower-cased without
   `-` and `_`, is in `schemeKeys` (`authorization`, `proxyauthorization`, `auth`: an authorization scheme whose credential
   the `auth-header` rule finds; `password=Bearer` is a value), or, when `verdict` is `string`, made only of units of
   `digitClass` (`max_tokens: 5`, `tokenCount: 5` stay). **A value longer than `keptMaxLength` is never kept**: the tests
   above would otherwise cost the whole run at every pair, and no stand-in or status word is that long. A kept value
   changes nothing the old rules do: the quoted and unquoted pair rules still redact `password: required`.
   A `string` verdict is a plural or a count word (`tokens`, `max_tokens`), an `any` verdict is a singular key
   (`password`, `token`, `otp`, `DB_PASS`, `signing_key`).
4. Otherwise output the range. After a quoted value the search restarts at the closing quote; after an unquoted value
   at `from`, the start of the value, so that a pair inside the value (`auth: password: hunter2`, `Cookie: secret="x"`)
   is found too: its own range is inside or next to the outer one and the merge unions them.

### 4.19 The `pii` group and `email`

The opt-in group of section 9.5: the rules of `pii`, run after the rules of the mode, in this order: `email`, `phone`,
`ip`, `otp`. They are `regex` rules (4.1) with the filters of 4.1; placeholders are `[REDACTED:email]`,
`[REDACTED:phone]`, `[REDACTED:ip]`, `[REDACTED:otp]` (section 7). Their hits go into the same merge as the secret rules:
where a PII range touches a secret range the group keeps the id of the earlier start (so `https://u:pass@host.example`
with the option on becomes `https://u:[REDACTED:url-credentials]`, the host included: the email rule covers
`pass@host.example`).

`email`: the standard is the WHATWG "valid e-mail address" (html.spec.whatwg.org/multipage/input.html), narrowed to
what prose carries. A local part of 1 to 64 units of `[A-Za-z0-9._%+-]`, `@`, a host of units of `[A-Za-z0-9.-]` (1 to
253), a last label of 2 to 24 ASCII letters and a word boundary. The last label is not a **file extension**
(`ignoreSuffixes`, a list of lower-case suffixes such as `.png`, `.json`, `.ts`): `icon@2x.png` stays. A host with no
letters-only last label (`react@18.2.0`, `pkg@1.2.3`) and a host without a dot (`user@localhost`) do not match.

### 4.20 `phone`

The standard is ITU-T E.164 for numbers with a `+` (country code and national number, at most 15 digits), plus the
North American Numbering Plan (NANP) and the common grouped national forms. Five entries, each a `regex` rule:

1. `+` and 8 to 15 digits, each digit optionally preceded by one of ` `, `.`, `(`, `)`, `-`, and a word boundary
   (`+44 20 7946 0958`, `+33.1.99.00.12.34`, `+493023125123`). A run of more than 15 digits **without separators** is not a
   number (`+12345678901234567890`: the word boundary after the 15th digit fails); with separators the first 15 digits
   are a number (`+1 2 3 4 ... 7` gives `[REDACTED:phone] 6 7`), because the pattern cannot count digits beyond its limit.
2. NANP with the area code in parentheses, optional `+1` first: `(415) 555-0123`, `+1 (415) 555-0123`.
3. NANP with separators: three, three and four digits separated by one of ` `, `.`, `-`, optional `+1` or `1` first:
   `415-555-0123`, `1-415-555-0123`.
4. National form with the trunk prefix `0`: `0`, 2 to 4 digits, then groups of 3 to 4 and 3 to 4 digits
   (`020 7946 0958`).
5. National form in pairs: `0`, one digit, then four groups of two digits (`01 99 00 12 34`).

A run of digits **without a separator** and without a `+` is never a number (`Request ID 1234567890`,
`/devices/1234567890`), nor are dates and times (`2026-11-19 10:00:59`), nor versions (`v0.3.0`).

### 4.21 `ip`

Three entries. The range is the address only (a port stays: `192.0.2.123:8080` gives `[REDACTED:ip]:8080`).

1. **IPv4**, RFC 791 dotted quad: four decimal octets 0 to 255 without leading zeros between word
   boundaries, and `ignoreAfterWords` `v`, `version`, `build`, `android`, `ios`, `firmware`, `sdk`, `os`, `kernel` with `afterGapClass` of whitespace, `:` and
   `=`: a version context keeps the text (`version 1.2.3.4`, `android 14.0.0.1`). `v1.2.3.4` has no word boundary and
   `999.1.1.1` no octet, so neither matches.
2. **IPv6, bare**: a run of 4 to 45 units of `[0-9A-Fa-f:]` that ends with a hexadecimal digit or with `::`, whose
   neighbours are not part of something longer (`ignoreBeforeClass` `[0-9A-Za-z_:]`, `ignoreAfterClass` `[0-9A-Za-z_]`: a
   colon before the run is part of it, so `::ffff:abcd:1234` and `2001:db8:1::` are whole), and that passes the check
   `ipv6` (5.8) with at least 3 colons (`2001:db8::1`). A run with fewer colons (`fe80::1`) is not matched, and neither is a
   run that is not an address (`std::vector` has a word unit before its `d`; the MAC address `aa:bb:cc:dd:ee:ff` has six
   groups and no `::`).
3. **IPv6 in brackets**: `[` , 2 to 45 units of `[0-9A-Fa-f:]` as `group` 1, `]`: the check `ipv6` with at least 2 colons
   (`[fdab::cafe]:8080`, `[::1]`); the brackets and the port stay.

The standards are RFC 4291 section 2.2 (text forms) and RFC 5952. A zone id (`%eth0`) and an IPv4 tail
(`::ffff:1.2.3.4`) are not part of the IPv6 forms; the IPv4 tail is found by the IPv4 entry.

### 4.22 `otp`

The standards are RFC 4226 and RFC 6238 (codes of 6 to 8 digits). The range is the digits (`group` 1); the noun stays.
Two entries:

1. **An explicit noun**, 4 to 8 digits: the macro `OTP_NOUN` (`OTP`, `OTP code`, `passcode`, `verification code`,
   `security code`, `confirmation code`, `auth code`, `authentication code`, `login code`, `MFA code`, `2FA code`,
   `SMS code`, `one-time password`, `one-time code`, `Bestätigungscode`, `Verifizierungscode`, `Sicherheitscode`,
   `Einmalpasswort`, `code de vérification`, `code de sécurité`, `code de confirmation`, matched with either case of the ASCII
   letters only (`BESTÄTIGUNGSCODE` with a capital `Ä` is not matched), after a word boundary) or the macro `OTP_NOUN_CJK` (`验证码`, `驗證碼`, `校验码`, `动态码`, `認証コード`, `確認コード`,
   `認証番号`, `確認番号`, `ワンタイムパスワード`), then the macro `OTP_JOIN`: up to three units of whitespace, `:`, `=` or `：`,
   optionally one of `ist`, `is`, `est`, `lautet`, `为`, `是`, `は` and up to three more separator units.
2. **The bare noun `code`**, 6 to 8 digits (`your code is 123456`; `your code is 4821` stays), unless the word before it
   (4.1) is `error`, `exit`, `status`, `response`, `postal`, `zip`, `area` or `country` (`ignoreAfterWords`, `afterGapClass`
   whitespace): `error code 123456`, `exit code 1370`, `response code 200000`, `postal code 941031` stay.

The digits end at a word boundary: a longer run is not a code. Numbers under a key (`max_tokens: 5`, `port 8080`) are not
OTP codes; a code under a key such as `otp` is the JSON key rule's business (section 6), with or without the option.

## 5. Shared algorithms

### 5.1 Guarded run

`guardedRunEnd(from, plainChar, escapeStop, max)`: starting at `i = from`, while `i < length` and `i -
from < max`: the unit `u = text[i]` extends the run when it is in `plainChar`, or when `u` is `\` and
the next unit exists and is **not** in `escapeStop` or does not exist (a backslash that does not begin
an escape such as `\"` or `\\`). Otherwise stop. Return `i`. (`plainChar` never contains `\`.) Linear.

### 5.2 `labelStart(k)`

Start of the identifier that holds the keyword at `k`: `s = k`; while `s > 0` and `k - s < labelLookback`
(64) and `text[s-1]` is in `identChar`: `s -= 1`. Return `s`.

### 5.3 `trimQueryValue(label, [a, b))`

Inside a URL query a value ends at the next `&`. If `text[label - 1]` is not `?` and not `&` (or `label
== 0`), return `[a, b)`. Otherwise let `i` be the first index in `[a, b)` of `&`; if there is one, return `[a, i)`; else `[a, b)`.
**The search stays inside the value range**: looking for the next `&` to the end of the text (and only then
comparing with `b`) gives the same result but is quadratic on `?token=` repeated.

### 5.4 Value evidence

`hasValueEvidence(raw)`, parameters `evidence` of `algorithms.json`:

1. `u` = `raw` without one leading and one trailing quote unit (a unit in `quoteChars`, `'` and `"`),
   each removed independently (a lone quote unit gives the empty string).
2. If `u` is a whole placeholder (section 7: the anchored placeholder grammar matches all of `u`),
   return false.
3. If `isTrivialValue(u)` return false.
4. Count how many of the four classes `[a-z]`, `[A-Z]`, `[0-9]`, `[^A-Za-z0-9]` occur in `u` (each class
   counts once; the last one is any unit that is not an ASCII letter or digit). If the count is at
   least `minClasses` (3), return true.
5. Return `entropy(u) >= entropyThreshold` (3.4).

**entropy(u)**, exact steps (the reference is the TypeScript code, run on Node):

1. `n` = the length of `u` in UTF-16 **units**. If `n == 0` the entropy is 0.
2. Walk `u` by code point (a surrogate pair is one symbol; a lone surrogate is one symbol). Keep a count `c` per
   symbol in a map that remembers the order of **first occurrence** (insertion order; Go maps are unordered,
   keep a list).
3. `H = 0.0` (IEEE 754 double). For each symbol in first-occurrence order: `p = c / n` (a double division;
   `n` is the unit length, larger than the number of symbols when astral characters are present, so the
   probabilities do not sum to 1); `H = H - (p * log2(p))` (the product is rounded to a double, then the
   subtraction). The order matters: two orders of the same counts differ in the last digits.
4. The comparison is `H >= 3.4` in double arithmetic (`3.4` is the double nearest to 3.4).

`log2(p)` for `0 < p <= 1` is the **fdlibm `__ieee754_log2`** (FreeBSD `e_log2.c`), the function V8 uses for
`Math.log2`. Platform functions are not conforming unless they return the same double: JavaScriptCore (Bun)
and the common C libraries differ from V8 in the last bit for some arguments (measured: of the 20,099 values
`log2(c/n)` with `2 <= n <= 200`, 214 differ in the last digits between Node and Bun). An implementation MAY use its
platform `log2` only after checking it against this table, which is the Node output:

| `p` | `log2(p)` | `p` | `log2(p)` |
|---|---|---|---|
| 1/3 | -1.5849625007211563 | 1/22 | -4.459431618637297 |
| 1/7 | -2.807354922057604 | 7/44 | -2.652076696579693 |
| 2/9 | -2.1699250014423126 | 1/13 | -3.700439718141092 |
| 3/22 | -2.8744691179161412 | 1/10 | -3.321928094887362 |
| 5/13 | -1.3785116232537298 | 3/4 | -0.4150374992788438 |
| 3/17 | -2.502500340529183 | 11/29 | -1.398549376490275 |
| 1/1000003 | -19.931572897402805 | 17/19 | -0.1604646721932461 |

A decision is only at risk when `|H - 3.4|` is below about 1e-9. `vectors/entropy.json` holds values 1e-5 to
1e-4 on both sides of the threshold (with the same counts in different first-occurrence order) and values
whose entropy only comes out right when `n` is the unit length. Exactness inside the 1e-9 band is
specified by this section, not covered by vectors.

### 5.5 Trivial values and stand-ins

`isTrivialValue(raw)` (`trivial` in `algorithms.json`): `v = lower(trim(raw))`. True when `v` is in
`words` (`undefined`, `null`, `changeme`, `example`, `placeholder`, `password`, `secret`, `token`); or `v`
is non-empty and every unit equals one `maskChars` character (`x` or `*`, so `xxxx` and `****`); or `v`
has length at least 2, starts with the first and ends with the second of a `wrappers` pair (`<` `>`,
`{` `}`), and every unit between them is in `wrapperInner` (any unit that is not a line terminator:
U+000A, U+000D, U+2028, U+2029). (The wrapper test is the JavaScript `^<.*>$`: the test walks the **UTF-16 units** between the wrapper
characters, so an astral character (two units) or a lone surrogate is allowed inside, `<🔑>` is a stand-in.)

`isDocPlaceholder(raw)`: `v = lower(trim(raw))`. True when `v` starts with one of `prefixes`
(`your`, `my`, `the`, `replace`, `insert`, `example`, `dummy`, `sample`) followed by a unit in `separator`
(`_` or `-`), or ends with one of `suffixes` (`here`) preceded by a unit in `separator`. (`your_api_key_here`,
`REPLACE_ME_TOKEN`.)

### 5.6 Letter guard

`passesLetterGuard(text, i)` is the upstream lookbehind `(?<!\p{L})`: true when `i == 0` or the code point that
ends at `i` is not a letter. The code point before `i` is the pair `text[i-2], text[i-1]` when `text[i-1]` is a
low surrogate and `text[i-2]` a high surrogate (one astral code point), else the unit `text[i-1]` (a lone
surrogate is not a letter). A letter is a code point of `algorithms.json` `letters.ranges`: the Unicode 15.0.0
General Categories Lu, Ll, Lt, Lm and Lo as sorted, merged ranges `lo-hi` (hex, a single code point without a
dash) joined by `,`, generated by `tools/gen-letters.ts` from `UnicodeData.txt` 15.0.0 (SHA-256 pinned in the
generator). No language uses its own `\p{L}` (the runtimes differ in Unicode version); the table is the
definition. The generator reports the code points where a runtime's `\p{L}` differs from the table (Node 26,
Unicode 17: only code points added to Unicode after 15.0).

### 5.7 Base64 JSON check

`isBase64Json(s)` (the 1Password token, `check: base64-json`; `s` has only units of `[A-Za-z0-9+/=]`):

1. **Decode** (WHATWG forgiving base64): if `length(s)` is a multiple of 4 remove one or two trailing `=`; if
   `length mod 4 == 1` it fails; a unit outside `A-Za-z0-9+/` (an `=` left in the middle or at a length that is
   not a multiple of 4) fails. Every 6 bits give a byte; bits that do not fill a byte are dropped. Each byte is one
   unit (Latin-1; no UTF-8 decoding).
2. The bytes are **one JSON text** (ECMA-404: whitespace only space, tab, LF, CR; literals `true false null`;
   numbers `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`; strings with units from U+0020, the escapes `\" \\ \/
   \b \f \n \r \t` and `\uXXXX`; no trailing comma) whose top value is an **object or array**. The check is
   iterative (no depth limit): do not use a library parser.

### 5.8 The `ipv6` check

`isIpv6(text, minColons)` (the `check` `ipv6` of 4.1; `text` has only units of `[0-9A-Fa-f:]`): false when `text` has fewer
than `minColons` colons. Split `text` at the text `::` (non-overlapping, left to right). More than two parts: false. One
part (no `::`): true when it has exactly 7 colons and each of its 8 groups (the text between colons) is 1 to 4 hexadecimal
digits. Two parts: each side is empty (no groups) or a list of groups separated by `:`, every group 1 to 4 hexadecimal
digits (so `:::` or a leading single colon is false); true when the groups of both sides together are fewer than 8
(`::` stands for at least one group of zeros, RFC 4291).

## 6. Key names

Which object keys name a secret. One predicate for every walker. Data: `keys.json`.

**Words of a key** `words(key)`: scan the key left to right; at each position try, in this order:

1. a run of capital letters `A-Z`; if the unit after the run is a lower-case letter `a-z` and the run
   has at least two capitals, the run without its last capital (that capital begins the next word);
   if the run has one capital and a lower-case letter follows, this alternative does not apply; if
   no lower-case letter follows, the whole run;
2. an optional capital and then a run of at least one lower-case letter;
3. a run of digits `0-9`.

The first alternative that applies gives a word; scanning continues after it. If none applies the
position advances by one unit (separators and all other characters are skipped). Each word is then
lower-cased. (`clientSecret` gives `client secret`, `APIKey` gives `api key`, `x-auth-token` gives `x
auth token`, `ABc` gives `a bc`.)

`sequences` = `secretWords` followed by `extraSequences`. `joined` = for each sequence of at least two
words, its words concatenated, plus `joinedExtra`.

`matchKey(key, plural)`:

1. `compact` = `key` lower-cased (the `lower` of section 3, plus U+0130 `İ` mapped to `i`) with every
   unit outside `a-z 0-9` removed. If `compact` is in `exactKeys`, true.
2. `w = words(key)`. If the last word equals `passLastWord` (`pass`), true.
3. For each word `x` of `w`: `base = plural ? x without one trailing "s" : x`. True when `x` or `base` is in
   `joined`; or `base` ends with a word of `suffixWords`; or `x` starts with a word of `prefixWords`.
4. For each sequence `S` and each start index `i` of `w`: true when for every `j`, `w[i + j] == S[j]` or
   (`plural` and `w[i + j] == S[j] + "s"`). (`w[i + j]` beyond the end of `w` is not equal to anything.)
5. Otherwise false.

`isSecretKeyName(key) = matchKey(key, true)`.

**Verdict** `keyVerdict(rawKey)`: `key` = `rawKey`, or when `rawKey` contains the text `[REDACTED` the
literal segments of `rawKey` (the text between placeholders, section 7) joined with one space. (A key
that was itself redacted is classified without its placeholders, so a second pass gives the first
verdict.) Then: if not `matchKey(key, true)`: `none`. If not `matchKey(key, false)`: `string` (only a
plural matched). If any word of `words(key)` is in `countWords` (`count`, `limit`, `max`, ...): `string`.
Otherwise `any`. So `pin` is `any`, `max_tokens` is `string`, `tokens` is `string`.

`strongerVerdict(a, b)`: `any` if either is `any`; else `string` if either is `string`; else `none`.

**Leaf placeholder** `leafPlaceholder(verdict, value)`: `none`: no replacement. A string: no replacement
when empty or a whole placeholder, else the placeholder `[REDACTED:key-context]`. A number: the placeholder
when `verdict` is `any`, otherwise none. Any other primitive (`null`, boolean): none.

The default **skip keys** are `type` and `id` (`structuralSkipKeys`): in `compat` a primitive value under such
a key is kept byte for byte and never scanned; in `strict` a string is scanned (9.3). Containers under skip
keys are walked.

**Public API.** `isSecretKeyName(key)` and `keyVerdict(key)` are public in every language. The verdict (`none`,
`string`, `any`) is the value-shape rule behind `max_tokens` staying visible while `pin` and `password` numbers
are replaced; a caller that redacts structured data of its own (headers, form fields) needs it, so a language
MUST NOT hide it behind the JSON walker. Names follow the language (`keyVerdict`, `key_verdict`, `KeyVerdict`);
the results are the strings `none`, `string`, `any`.

## 7. Placeholders, hits and splicing

**Placeholder grammar** (`patterns.placeholder`): `[REDACTED` then optionally `:` rule `[^\[\]:WS]+` and
optionally `:` suffix `[^\[\]]*`, then `]`. So `[REDACTED]`, `[REDACTED:rule]` and
`[REDACTED:rule:suffix]` are placeholders. `placeholderEndAt(text, i)` is the end of the longest such
placeholder that starts exactly at `i` (the grammar has one match length per start), or `-1`.
A **whole placeholder** is a string that is exactly one placeholder from its first to its last unit. The
end anchor is the end of the text and nothing else: a placeholder followed by a final line terminator
(LF, CR, U+2028, U+2029) is **not** a whole placeholder (`{"token": "[REDACTED]\n"}` is replaced). An
implementation uses a full-string match (`fullmatch`, `\A...\Z`); Python `$` and Go/Python `re.match` with
`$` accept a final `\n` and are not conforming. Vectors in `nested-json.json` cover all four terminators.
`literalSegments(text)` is `text` split by every (non-overlapping, left to right) placeholder; it has
one more element than there are placeholders; empty elements are kept.

**Numbered form (decided 2026-11-18).** The rule part of a placeholder may end with `#<n>`
(`[REDACTED:npm#2]`): the grammar above already admits it (`#` is a unit of the rule class), and it is a
placeholder like any other (whole-placeholder tests, `isPlaceholderValue`, idempotence, `literalSegments`,
restore). Only object-key collisions write it (section 8, **key collisions**; it goes inside the last
placeholder of a key, also of a key that merely contains placeholders).

**Read form**: `[REDACTED:` + `shorten(ruleId)` + `]`, where `shorten` removes one leading prefix of
`stripPrefixes` (`@secretlint/secretlint-rule-`, then `mobilerun-redaction/`, tried in that order, each
at most once). Rule ids written by the standard tier have no prefix. No unit of the secret appears in
the placeholder. (The 0.1.1 `last4` form is a TypeScript extension, section 13.)

**merge(hits)**: stable-sort by `start` ascending (equal starts keep their order: pipeline order, then
the order the rule returned them). Then fold: keep a list; for each hit `(id, s, e)`: if the list is
non-empty and `s <= last.end` (overlapping or touching), set `last.end = max(last.end, e)` and keep
`last.id` (the id of the earliest-starting hit of the group, the first listed on equal starts);
otherwise append `(id, s, e)`. The result is sorted, non-overlapping and non-touching.

**splice(text, hits)**: `h = merge(hits)`. Output = for each hit in order the text between the previous
end and `start`, then the read placeholder of its id; finally the text after the last end. Hits whose
range is empty (`s == e`) still produce a placeholder.

## 8. JSON contract

A **JSON value** is what a JSON parser produces: object, array, string, number, boolean, null.

- **Order.** Traversal and output order of object keys is the ECMAScript own-property order: keys that
  are canonical array indices (the decimal strings `0` to `4294967294` without leading zeros or sign)
  in ascending numeric order, then the other string keys in insertion order. An implementation that
  parses JSON MUST use an order-preserving decoder and apply this order when it walks (Go has no
  ordered `map`; Python dicts keep insertion order and need the index-keys-first step).
- **Duplicate keys.** The input has been parsed, so for duplicate keys the last value wins and the key
  keeps the position of its first occurrence (as in ECMAScript); only the surviving value is walked.
  Two different keys can also become the same key after redaction (two keys that each held a secret
  give the same placeholder text). **Key collisions (decided 2026-11-18): no value is lost.**
  Let the *output key* of an entry be its key after redaction (the key scan of section 9, size-limit
  placeholders included), and call a key **changed** when its output key is not the key itself. The rules, for
  one object, in contract order:
  1. **Reserved names.** Before the first entry, scan every input key that contains the text `[REDACTED` (no
     budget charge, no hits, the same key scan as the walk) and **reserve** each one the scan leaves as it is.
     In `strict` the scan covers only the keys, in contract order, whose running total length (with the keys
     before them in the object) stays within the remaining `chars` budget; a later key becomes the size-limit
     placeholder anyway (9.3), so it cannot be left as it is. A key over `sync.maxKeyChars` is not scanned. A key that
     redaction leaves unchanged always keeps its own name, whatever else collides; a changed key never takes a
     reserved name.
  2. A changed entry whose output key is neither reserved nor the name of an earlier entry of the object is
     stored under its output key.
  3. Otherwise (the name is reserved or taken), the entry gets a number. Take the **last placeholder** of the
     output key (the last match of the placeholder grammar, section 7). If it is exactly `[REDACTED:<rule>]` (a
     rule, no `:suffix`, and a rule that does not itself end with `#<digits>`), the entry is stored under the
     output key with `#<n>` inserted before the `]` of that last placeholder: `[REDACTED:npm#2]`,
     `token [REDACTED:npm#2] end`, `password=[REDACTED:generic-keyword#2]`. `n` starts at 2 and counts up per
     object and per output key in contract order; a number whose name is reserved or already in the output
     object is skipped. The `[REDACTED:size-limit]` key of a key over the limit or of a collapsed rest (9.3) is
     a changed key like any other; an entry written under a node limit (9.2 step 6) is an unchanged key.
  4. Any other output key (no placeholder, a last placeholder with a `:suffix`, the bare `[REDACTED]`, an
     already numbered last placeholder) keeps the old rule: the later value replaces the earlier one and the
     key keeps the earlier position.
  The first entry therefore keeps the plain key unless that name is written in the input, in which case the entry
  written there keeps it and the changed key is numbered. Idempotence: the next pass leaves a numbered key as it
  is (a placeholder is not a secret), so redacting the output gives the output.
- **Numbers.** A number under a key whose verdict is `any` is replaced as a unit by `[REDACTED:key-context]`.
  Every other number is untouched in value: its digits are never scanned. The data model is the IEEE 754
  double: a JSON number is parsed to the nearest double, and **equality of outputs is value equality** of
  those doubles. A serializer writes a double the way ECMAScript `Number::toString` does, so `1.0` is written
  `1`, `1e2` is `100`, `1E+21` is `1e+21`, `-0` is `0`, and an integer beyond 2^53 is the nearest double
  (`9007199254740993` becomes `9007199254740992`). `NaN` and the infinities are not JSON.
  **Equality across languages is compared at double level**: vectors and the corpus compare parsed values
  converted to doubles, never number text. A language with exact integers (Python `int`, Go `json.Number`)
  MUST return every number it does not replace **unchanged and exact** (the integer `9007199254740993` stays
  `9007199254740993`); it does not round to a double. TypeScript has only doubles and is unchanged: its output
  is the double. A differential run converts both sides to doubles before comparing.
- `null` and booleans are untouched. The empty string is untouched.
- **Strings** are scanned as texts (4) and a string under a secret key is replaced whole (section 6 and 9).
- **Keys** are redacted: a key of length up to 4096 is scanned (from 8 units in `compat` without `pii`, as texts are; from 1 in `strict` and with `pii`) with the `detect` of the tier (the standard
  rules of the mode and, with the `pii` option, the `pii` rules; in the full tier the full-tier rules too, 9.4) and spliced
  when it holds a secret or a personal datum (it
  can hold one, e.g. `{"password=hunter2xx": 1}`, or in the full tier a key that is itself an npm token); a shorter
  key cannot match and a longer one is left as it is in `compat` (strict: section 9).
- **Invalid JSON.** A JSON entry point that takes JSON **text** (Python and Go; the TypeScript entry points take
  values, not JSON text, so this does not apply to them) and receives text that is not valid JSON returns, as
  its value, the text-tier redaction of the raw input (section 9.1, so nothing unscanned is returned), together
  with an invalid-JSON error indication in the language's idiom (Go: the redacted bytes and `ErrInvalidJSON`;
  Python: a result flag or an exception that carries the redacted text). It never returns the raw input.
- Non-JSON values (`NaN`, infinities, functions, symbols, dates, class instances, cycles) are out of
  contract. TypeScript handles them as section 13 says; other languages MAY reject them.

## 9. Tiers and modes

**Tiers**:

- `standard`: the rules of section 4.
- `full`: the standard rules plus the **full-tier rules** (`rules.json` `full`, sections 4.11 to 4.17): the
  secretlint preset `@secretlint/secretlint-rule-preset-recommend` 13.0.4 without `filter-comments` and `gcp`, AWS
  key id and account id scanning on, ported into the spec (INVENTORY.md). The full tier's `detect` is the merge of
  its rules' hits and the standard hits (4.17). Every implementation has the full tier. The full-tier rules see
  only the first `full.scanCap` (2,000,000) units of a text, in windows of `full.scanWindow` (100,000) units that
  overlap by `full.scanOverlap` (10,240) (stride = window minus overlap, last window ends at the cap; the hits of
  a window are moved by its offset and merged); the standard rules always see the whole text. A text longer than
  the cap is reported as the event `redaction.scan.capped`.

**Entry points** (TypeScript names; the contract is language neutral): redact a text, redact a JSON
value; each in the `standard` tier (the sync entry) and the `full` tier (the async entry). Every entry point takes the
mode and the boolean option `pii` (default false, 9.5).

**Modes**:

- `compat` (TypeScript default; reproduces v0.2.0). The rule list is the `compat` list of 4.10 and the output is
  byte-identical to v0.2.0 (the golden corpus pins it). The standard tier fails closed. The full tier fails
  open: when its rules fail it falls back to the standard rules, and a text beyond the scan cap is
  scanned by the standard rules only.
- `strict` (Python and Go default; an option in TypeScript). **No path returns text that was not scanned.**
  Any internal error, cap or limit gives an error placeholder or `[REDACTED:size-limit]` for the unscanned
  remainder. Its rule list is the `strict` list of 4.10, a superset of the 0.3.0 list: the short-secret fixes (short values
  under secret keys in text, escaped-quote keys and the `=>` separator, every `dr_sk_` form, the full Bearer credential)
  exist in `strict` only, and a text of any length is scanned.

### 9.1 Text, standard tier

`redactText(text, maxChars)` returns `(text, hits)`:

1. If `length > maxChars` (default `sync.maxChars`, 4,000,000): return `[REDACTED:size-limit]` with the hit
   `(size-limit, 0, length)`.
2. If `length < 8` in `compat` without `pii`: return the text and no hits (in `strict`, and with `pii`, the text is scanned).
3. `hits = detect(text, mode, pii)`; return `splice(text, hits)` and `hits` (already merged).
4. An unexpected failure at any point (both modes): return `[REDACTED:redaction-failed]` and the hit
   `(redaction-failed, 0, 0)`.

### 9.2 JSON value, standard tier, `compat`

State: `nodes = maxNodes` (default 500,000), `chars = maxChars` (4,000,000), `maxDepth` (64), skip keys
(`type`, `id`), `hits` (receives the hits: rule id and range, section 11). `limit(id)` appends `(id, 0,
0)` and gives the read placeholder of `id`. `walk(value, depth, verdict)`:

1. If `nodes <= 0`: `limit(size-limit)`. Else `nodes -= 1`.
2. A string: empty is returned. `leafPlaceholder(verdict, value)` replacement: append `(key-context, 0,
   length)` and return the placeholder. If `length > chars`: `chars = 0`, `limit(size-limit)`. Else `chars -=
   length`, scan as a text with no length cap, append its hits, return its text.
3. Any other primitive: `leafPlaceholder`; a replacement appends `(key-context, 0, 0)`.
4. A container with `depth >= maxDepth`: `limit(depth-limit)`. (The root has depth 0; a container is walked
   when its own depth is below the limit; a primitive is never depth-limited.)
5. An array: for each element in order: if `nodes <= 0`: append `limit(size-limit)` as the next element and
   stop; else the element is `walk(element, depth + 1, verdict)`.
6. An object: for each key in contract order: if `nodes <= 0`: store `limit(size-limit)` under the key as it was
   (an unchanged key: it keeps its name, section 8 **key collisions**) and stop. Else `outKey` = the key redacted (section 8, with its hits appended to `hits`). If the
   key is a skip key and the value is a primitive: `nodes -= 1`, `out[outKey] = value` unchanged (`compat`; strict
   scans a string, 9.3). Else
   `out[outKey] = walk(value, depth + 1, strongerVerdict(verdict, keyVerdict(key)))`.
7. The root call is `walk(value, 0, none)`. Any unexpected failure replaces the whole value by
   `[REDACTED:redaction-failed]`.

Counting rule worth stating: a string that does not fit in the remaining `chars` empties the budget, so
every later non-empty string that is not under a secret key is `[REDACTED:size-limit]`.

### 9.3 JSON value, standard tier, `strict`

The walk is **iterative** (explicit stack; no recursion, no stack overflow) and keeps to the same limits
(`strict.maxChars`, `strict.maxDepth`, `strict.maxNodes`, same defaults). It differs from `compat`:

- `limit` placeholders replace anything not scanned: node, character or depth limit, an over-long key, a
  value outside the JSON model (`[REDACTED:redaction-failed]`), a cycle (`[REDACTED:circular]`).
- A key is scanned by the same leaf scan as a string leaf: the rules of the `strict` list (4.10), and the `pii` rules
  when the option is set, whatever its length (`{"token=hunter2": 1}` gives the key `token=[REDACTED:generic-keyword]`).
- Keys count against `chars` (their length) too. A key longer than `sync.maxKeyChars` (4096) or longer than
  the remaining `chars` empties the budget and is replaced by `[REDACTED:size-limit]`.
- When `nodes` runs out inside a container, the rest of the container is **collapsed**: an array gets one
  more element `[REDACTED:size-limit]`; an object gets one entry whose key and value are both
  `[REDACTED:size-limit]` (the key of the first unscanned entry is raw text and is not returned). The
  container is then complete.
- A leaf scan that fails gives `[REDACTED:redaction-failed]` for that leaf.
- **Skip keys exempt a value only from the key-context replacement.** A string under a skip key (default `type`,
  `id`) is scanned as a text like any other leaf (a token under `id` is redacted) and is not replaced by
  `[REDACTED:key-context]` even when an ancestor key is secret; a number, boolean or `null` under a skip key is
  returned unchanged (there is nothing in it to scan). Strict therefore **never returns text that was not
  scanned, without exception**. `compat` is unchanged (9.2: the skip-key string is returned as it is).
- **Decided 2026-11-18:** the strict details above are accepted as written: a `Date` or class instance
  (anything that is not a plain object, array or primitive) becomes `[REDACTED:redaction-failed]`, keys count
  against `maxChars`, and the rest of a node-exhausted object collapses into one `[REDACTED:size-limit]` key.

Everything else (order, verdicts, number handling, key redaction) is as in 9.2.

### 9.4 Full tier

- `compat`: text: `detect` is the full-tier rules over the first `scanCap` units (windowed) plus `detect`
  over the whole text, merged (4.17); splice. A detector failure emits the event `redaction.detect.failed` with the
  error class only, then returns the result of `detect` alone, or `[REDACTED:error]` with the hit `(error,
  0, 0)` if that fails too. JSON: each string leaf is a text of this kind; **keys are scanned with the full tier's `detect`
  (4.17, no windows: a key has at most `sync.maxKeyChars` units), not only the standard rules** (decided
  2026-11-18; the standard rules are those of the mode, 4.10, and the `pii` rules when the option is set), with the
  key rules of section 8 otherwise unchanged; no depth, node or character limit (a TypeScript behaviour kept for compatibility).
- `strict`: text: **first** the total-character cap as in 9.1: a text longer than `strict.maxChars`
  (4,000,000) is replaced whole by `[REDACTED:size-limit]` with the hit `(size-limit, 0, length)`, before any scan
  (no scan work is spent on it). Then as `compat`, except that a detector failure returns `[REDACTED:error]`
  (no fallback), the units beyond `scanCap` are replaced by `[REDACTED:size-limit]` (the hit `(size-limit, cap,
  length)` is merged with any hit it touches), and `last4` is ignored (no hit of the strict mode carries a
  character of the text: the placeholder is always the read form). JSON: the strict walk of 9.3 with each leaf scanned by this text rule and each key scanned with the
  full tier's `detect` of the `strict` mode (4.10) and the `pii` rules when the option is set (the key size rules of
  9.3 are unchanged).

### 9.5 The `pii` option

`pii` (boolean, default false) is an option of every entry point, both tiers and both modes. When it is true, `detect`
(4.) runs the rules of `pii` (4.19 to 4.22) after the rules of the mode, and everything else is as without it: the
same merge and splice (section 7), the same limits, the keys of a JSON value scanned with the same `detect` (8), and
in `strict` the same walk (9.3). It adds the rule ids `email`, `phone`, `ip` and `otp`, and nothing else changes;
with the option false the output is byte-identical to the output of a version without the option. The option is
passed to the leaf scan of the full tier too (9.4: its hits are merged with the full-tier hits). It is **not** a mode and
not a tier: the same `pii: true` works in `compat` and in `strict`. Out of scope: names, postal addresses and any
detection that needs a model.

## 10. ReDoS rules

1. Every pattern passes `recheck` (the npm package `recheck`, a version released at least 7 days ago,
   pinned exactly) with status `safe`. Anything else fails the lint, with one bounded exception for a timing
   false positive: `recheck`'s fuzz checker measures time, so on a loaded machine it can call a safe pattern
   `vulnerable`. A `vulnerable` verdict is never erased by another run (no "a second seed says safe, so pass").
   Instead the **attack string `recheck` produced** (its pumps, prefixes and suffix) is built at 100 KB and 1 MB
   and run through the scaling harness of item 5 in JavaScript and Python. If the growth is super-linear (the
   same ratio and absolute bounds as item 5, or the run does not finish in 20 s) the lint fails and reports the
   attack. If the harness does not confirm it, the lint passes with a `WARNING` that carries the attack string,
   so the doubt stays visible in the log. A verdict `unknown`, or `vulnerable` without an attack string, fails.
   (`tools/lib/recheck-gate.ts`; the self-test plants the grammar-clean ReDoS `a*a*a*a*b` and expects it to fail
   with its attack.)
2. The grammar of section 2 bans nested quantifiers and unbounded lazy quantifiers, and bounds lazy
   quantifiers to 64.
3. An unbounded quantifier whose class overlaps the token that follows it needs a disjoint required literal
   after it (a rule of design; `recheck` and the scaling test enforce it).
4. Work per candidate is bounded or linear; a rule restarts a failed scan so that no unit is the start of
   more than a bounded number of attempts (`restart at matchStart + 1` only where the attempt did bounded
   work; `restart at the start of the rejected value` where it is linear).
5. `tools/lint-spec` runs two **scaling tests**. The first: generated attack strings (each unit of a list that holds
   unterminated quotes, repeated keywords of the key lists, `a-` runs, whitespace runs, escape runs,
   percent triples, PEM headers, key-format prefixes) are repeated to 100 KB and to 1 MB and run through every
   pattern in JavaScript and in Python. The time at 1 MB must not exceed 30 times the time at 100 KB (floor 10
   ms) and 3 s absolute. The second runs the same attack strings through the interpreter (`detectSyncHits` of the
   TypeScript package: every rule kind with its restart loops, not only the raw patterns) at the same sizes with the
   same ratio and a 10 s absolute bound. Each run is a subprocess under an external deadline; the three runs
   (JavaScript patterns, Python patterns, interpreter) start together. Before a measurement fails it is repeated
   up to twice and the best time per size counts (the retries are printed); the bounds do not change.
   Working on one rule: `bun tools/lint-spec.ts --only <rule id or kind>[,...]` runs the schema and rule checks and,
   for the patterns of the named rules only, grammar, compile, recheck and scaling (with the attack units that
   belong to them; the interpreter scaling only over the units of the selected full-tier rules), and prints what
   it skipped. The recheck verdicts are cached per pattern in `tools/.cache` (key: recheck version, gate settings,
   pattern; `--no-cache` analyses everything again). `--only-scaling` runs just the scaling stages. The full
   run without `--only` stays the gate, in CI as the jobs `spec` (`--skip-scaling`) and `spec-scaling`.
6. Every call has a total-character cap (`sync.maxChars`, `strict.maxChars`).

## 11. Metadata

- No `last4` in any code path of the spec (the 0.1.1 form is a TypeScript extension for old consumers).
- Python and Go hit statistics are `(rule id, count)` only. **Ranges are not exposed** (they reveal lengths).
- Error events carry the error class only, never the message (a message can echo input).
- Ported secretlint data drops its message templates (they print the secret).
- No input fragment, secret or matched text appears in an error, an event or a log line.
- The TypeScript `stats.hits` carry rule id and range (no text); that is a TypeScript extension kept for
  compatibility.

## 12. Spec integrity

Each language package **embeds** the spec: the data of `rules.json`, `keys.json` and `algorithms.json` is part
of the package itself, so a package runs without reading any file at runtime:

- TypeScript: a generated module (`ts/src/spec-data.generated.ts`) that holds the three files as constants and
  their hash. It uses no file system, no Node built-in and no `import.meta`, so every entry (including
  `./sync`) runs in any JavaScript runtime.
- Python: package data, or a generated module, as the implementation chooses. Go: a `go:embed` copy.
- `hash = SHA-256( for name in [rules.json, keys.json, algorithms.json]: name + NUL + bytes + NUL )`, hex,
  lower case, where NUL is the byte 0.
- **The hash is checked in CI, not at runtime.** `tools/sync-spec` generates the embedded form of every language
  from `spec/`; `tools/sync-spec --check` fails when any generated file differs from what it would generate
  (this covers the data and the hash). It runs in the CI jobs of the spec and of each language and, on the tagged
  commit, in the release workflow; each language also has a unit test that its embedded data equals the files of
  `spec/` and carries their hash. A language MAY additionally check the hash at import.
- At import/initialisation every package refuses to start (and MUST NOT process any input) on an unsupported
  `specVersion` or an empty rule set (no pipeline entries or no `secretWords`).
- Error messages for these failures name the failure, never the data.

## 13. TypeScript extensions

These exist for compatibility with v0.2.0 and never change what is detected:

- Async signatures and `bigint` values (a `bigint` counts as a number).
- `restoreRedacted(redacted, stored)` and its options (restores values behind placeholders from a stored copy). It
  also maps **placeholder keys** back: an incoming key that is or contains a placeholder (plain or numbered)
  is replaced by the one stored key of the same object whose redaction, named as in section 8 with the standard
  rules or the full tier, is exactly that key, and its value is restored against the stored value. No such stored
  key, more than one, or one that an earlier incoming key already took: the incoming key stays and the path is
  reported as a conflict. Paths of conflicts below a restored key are built from the key the
  client sent (the placeholder key), never from the stored key (a secret).
- The 0.1.1 `last4` placeholder `[REDACTED:<rule>:<last4>]` for matches of at least 16 units (`opts.last4`);
  brackets in the last four units are replaced by `*`. `last4` has no effect in `strict`.
- `CREDENTIAL_KEY_RE` (the 0.1.1 substring matcher; a TypeScript constant, not spec data), `STRUCTURAL_SKIP_KEYS`.
- Input shapes outside JSON in `compat`: `Date` is returned as is; typed arrays and buffers become
  `[REDACTED:size-limit]`; an `Error` is read as `{name, message, stack}`; an object with `toJSON` as its
  result; a cycle becomes `[REDACTED:circular]`; a non-string text is turned into a string.
- `detect` override, `onEvent` callback, `skipKeys` option.
- The hits of the full tier carry the 0.2.0 rule id `@secretlint/secretlint-rule-<id>` in `hits` (the placeholder
  shortens it to `<id>`, section 7); the other languages report `<id>`.
- The `last4` threshold (16) and masked characters (`[` and `]`).

All data of these extensions is **TypeScript constants in `ts/src`**, outside the hashed spec files: changing
one never changes the spec hash that Python and Go embed, and none of them affects detection of the standard
tier.

## 13a. Per-language API notes

The contract is language neutral; these points keep the languages from drifting in details a signature
can hide:

- **An explicit limit of 0 means 0.** `maxChars`, `maxDepth`, `maxNodes` (and any other numeric limit) given as
  0 are applied as 0 (a text over 0 characters is replaced whole); only an **omitted** limit means the default.
  A language whose zero value is indistinguishable from omitted (Go) takes pointer-valued limits, with a small
  helper to build them, instead of treating 0 as unset. (TypeScript uses `??`, so an explicit 0 already
  counts.)
- Defaults of the limits are the values of section 9; an implementation never hard-codes another default.
- `strict` is the default mode in Python and Go and an option in TypeScript (section 9).
- The key predicate and verdict are public (section 6).
- **Go: two deviations beyond the limits are allowed** (decided 2026-11-18), both fail closed and never
  leave text unscanned: (1) the strict parse budget of `RedactJSON` counts the strings of secret-named keys too
  (the other languages receive a parsed value, so they cannot meet this limit earlier than the walk does); (2) when
  the node limit cuts a container, the cut is made in document order (the order Go's streaming decoder sees the
  members), not in the contract order of section 8. Every cut part is replaced by `[REDACTED:size-limit]`.

## 14. Conformance vectors

`vectors/*.json`: `{ "description", "cases": [ ... ] }`. A case has `name`, `input` (or `inputGen`), an
optional `mode` (`compat` default, `strict`) and `opts` (`maxChars`, `maxDepth`, `maxNodes`, and the boolean `pii`), and either
`expected` (both tiers give the same output) or `expectedSync` and `expectedAsync` (the full tier finds more).
`inputGen` and `expectedGenSync` / `expectedGenAsync` give a long string as `{ "parts": [[unit, times], ...] }`,
the concatenation of each unit repeated. A string input runs through the text entry point, any other JSON
value through the JSON entry point. The output (a string or a JSON value) must equal the expected value
exactly; for JSON, object key order is compared as the contract order. Field names are fixed (consumers
read `expectedSync` / `expectedAsync`). Every vector must also be idempotent (redacting the expected output, with
the same mode and the same `pii` option, gives the same output).

The vectors cross every cap: text longer than `maxChars`, depth and node limits, leaf and key size limits,
the scan cap and the window overlap of the full tier. `corpus/` holds the seeded differential corpus
generator's recorded outputs for the TypeScript reference (`golden-*.json`); a differential job runs the
same seeded corpus through every implementation.

## 15. Known portability risks

- **Entropy comparison**: floating point. `log2` differs between engines in the last bit (Node and Bun
  already differ, so the TypeScript tests and production can disagree inside the band); section 5.4 fixes the
  summation order and the `log2` (fdlibm). A value within about 1e-9 of 3.4 can decide differently on a
  platform `log2`; the vectors and the corpus stay 1e-5 or more away from the threshold.
- **Percent decoding**: UTF-8 decoding of `%XX` runs must reject exactly what ECMAScript
  `decodeURIComponent` rejects (overlong forms, surrogate code points, truncated sequences); then the value
  is left whole (4.9).
- **Unicode letter guard** (full tier, 5.6): the table is pinned to Unicode 15.0.0 and is data of the spec; a
  language must not use its own `\p{L}`, `unicodedata` or `unicode.IsLetter`, whose Unicode version differs
  (the generator lists the code points where Node 26 differs: only letters added after 15.0).
- **Unit counting** (section 1): the most likely source of drift (astral characters inside values and keys,
  lone surrogates, invalid UTF-8 in Go).
- **Numbers**: the double model of section 8 is the contract; big integers are rounded, not preserved.

### Known detection gaps

These are limits of what the rules find, not portability risks. A vector pins what is found; a gap is not a vector
that expects the miss, so closing one later changes no existing vector.

- **Secrets in prose**: a secret that stands after a word and no separator is not found (`the password hunter2 was
  rejected`). `key-pairs` and the keyword rules need `:`, `=` or `=>`.
- **Internationalised email addresses**: `email` is ASCII (local part and host). An address with a non-ASCII letter or in
  Punycode form with a Unicode local part is not found.
- **URL-encoded values**: `person%40example.com`, `%2B441234567890` and a code inside an encoded query value are not
  decoded by the `pii` rules (the `key-context` rule decodes only the names of query parameters and one level of a nested
  query, 4.9).
- **Email local parts** longer than 64 units: the match starts 64 units before the `@`; what stands before is left.
- **Phone numbers**: only the `+` form, NANP forms and two national forms (4.20) are found; a number without separators
  and without a `+` is not, and a `+` number that is longer than 15 digits is not.
- **IPv4** needs four groups with word boundaries: the first four groups of a five-group version string (`1.2.3.4.5`)
  are an address, and a version is kept only after the words of 4.21. **IPv6** with fewer than three colons is found only
  in brackets (`fe80::1` is not; `[fe80::1]` is), and a zone id or an IPv4 tail is not part of the address.
- **OTP codes** need a noun of 4.22 in the same sentence, directly before the digits; a code in a table cell, a code
  split by spaces (`482 913`) and a code under a noun of another language are not found.
- **Key verdicts in text** (4.18) are those of JSON keys, so a design token such as `spacing_token: 16px` is redacted in
  `strict`, as `{"spacing_token": "16px"}` is in JSON.
- **Known over-redactions** (kept on purpose, not fixed here): `git@github.com:org/repo` is an email; `offset +10000000` is
  a phone number (a `+` and 8 digits); the Bearer credential of `strict` takes everything up to whitespace or a quote, so
  `Bearer abc)` takes the parenthesis.
- **Known misses** (also not fixed here): `+49 (0) 170 1234567` and `0049 170 1234567` (trunk digit in parentheses,
  `00` prefix); `config['password'] = 'x'` (the key is in quotes and brackets); a YAML block scalar (`password: |` and
  the indented lines after it); an unseparated number such as `4155550123`; `::1` and `fe80::1%eth0`; the version word
  list of 4.21 is not exhaustive (`ios: 10.0.0.1` with a colon is kept, `release 1.2.3.4` is not).
- **Template values**: `password="{hunter2}"` is redacted up to the closing brace (`{hunter2`), as in 0.3.0: the unquoted
  pair rule stops at a brace, and the quoted `{hunter2}` alone would be a stand-in (5.5).
