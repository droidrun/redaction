# Redaction spec

Normative description of what `droidrun/redaction` detects and how it rewrites text and JSON
values. The TypeScript package (`ts/`) implements it; Python and Go implement the same spec and
must give byte-identical output. The data lives next to this file (`rules.json`, `keys.json`,
`algorithms.json`); this document defines how to read it and every algorithm the data cannot
express. A Python or Go developer can implement the standard tier from this file and the
vectors alone, without reading the TypeScript.

Words in capitals (MUST, MUST NOT, MAY) are used in the RFC 2119 sense.

Contents: 1 Scope and units, 2 Portable grammar, 3 Spec files and macros, 4 Standard-tier
detection, 5 Shared algorithms, 6 Key names, 7 Placeholders, hits and splicing, 8 JSON contract,
9 Tiers and modes, 10 ReDoS rules, 11 Metadata, 12 Spec integrity, 13 TypeScript extensions,
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
  characters gives the same matches. Offsets are unit offsets. Go MUST match over the whole text
  with offsets, never over slices.
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
| rule id outside `^[a-z0-9-]+$` | ids are part of the placeholder |

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
- `pipeline`: the ordered rule list (section 4).

**Expansion.** Every string that is a pattern or a class is expanded before use: each `{{NAME}}`
is replaced by the macro `NAME`, repeatedly until nothing changes (nesting depth at most 8; more
is an error, an unknown name is an error). A string macro is inserted as is. A word macro is
inserted as `(?:` alternatives joined by `|` `)`; one alternative is its words joined by `J`
(J is pattern text, for example `[_-]?`); inside a word every ASCII lower-case letter `x` is
written `[xX]`, every other character as it is. The order of the alternatives is the order of the
list.

The macro `WS` is the exact JavaScript `\s` set written out, as characters (not escapes): U+0009,
U+000A, U+000B, U+000C, U+000D, U+0020, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F,
U+205F, U+3000, U+FEFF. It is used inside classes as `[{{WS}}]` or `[^{{WS}}...]`. Nothing else is
whitespace anywhere in the spec: **trim** removes characters of this set from both ends of a
string.

**Lower-casing** in the spec (`lower`) maps `A` to `Z` to `a` to `z` and U+212A (KELVIN SIGN) to
`k`, and changes nothing else. Every comparison of words and every `lower(x) ==` test below uses
it (JavaScript `toLowerCase` gives the same result on every string such a comparison can match).

`keys.json` (section 6) and `algorithms.json` hold word lists and numeric parameters; they are
named where they are used.

## 4. Standard-tier detection

`detect(text)` returns the merged hits of the standard tier.

1. Let `hits` be empty. For each rule of `pipeline` in order, run the rule kind below on the whole
   text. It returns ranges in the order given by its kind. Append `(rule.id, start, end)` for each
   range to `hits`. Several pipeline entries may share an id.
2. Return `merge(hits)` (section 7).

The rules never see a text shorter than `text.minScanLength` (8): `redact` returns it unchanged
(section 9). A range returned by a rule has `start <= end`; rules drop empty ranges where noted.

**Placeholder test of a range** `isPlaceholderValue(text, start, end)`: let `e` be the end of the
placeholder (section 7) that starts exactly at `start`, or none; true when `e` exists and `e >= end`.
This is the idempotence guard: a value that already is (the start of) one of our placeholders is
never redacted again.

Rule kinds. `P` is the expanded pattern text; `scan(P)` is the global search of section 2.

### 4.1 `regex`

Fields: `pattern`, optional `group` (default 0), `notBefore`, `notAfter`, `requireClass`,
`requireLiteral`, `dropPlaceholder`.

1. Find matches of `pattern` left to right. The candidate range is the whole match, or the span of
   capture group `group`.
2. **Guards** (only when `notBefore` or `notAfter` is present; they are allowed only on a pattern
   of fixed match length, so that resuming one unit later is exact). For a match `[s, e)`: it is
   refused when `s > 0` and the unit `text[s-1]` is in the class `notBefore`, or when `e < length`
   and `text[e]` is in the class `notAfter`. A refused match restarts the search at `s + 1`. An
   accepted match restarts at `e`.
3. **Filters** on the candidate, all that are present: `requireClass`: the candidate text contains
   a unit of the class; `requireLiteral`: it contains the literal; `dropPlaceholder`: it is not an
   `isPlaceholderValue`. A candidate that fails a filter is dropped (the search is not
   restarted: the match was consumed).
4. Output the surviving candidates in order.

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
   or `limit`. Let `f` be the first index at or after `b` where the literal `footerMarker`
   occurs in the whole text. If `f` exists, `f < bodyEnd`, and `footer` matches exactly at `f`
   (anchored there), then `covered = ` end of that match; otherwise `covered = bodyEnd`.
3. Output `[s, covered)`.

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

Fields: `bearer`, `scheme`, `valueClass`, `minValueLength`, `lowerClass`, `upperClass`,
`wordClass`, `plainWords`.

The rule output is all Bearer ranges in text order, then all scheme ranges in text order, with
both filtered by step 3.

1. **Bearer**: for each match of `bearer`, the range of capture group 1.
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

`percentDecode(x)` is URI component decoding (`%XX` sequences, UTF-8) that returns `x` itself,
unchanged, when it contains a malformed sequence (a bad `%` triple, a lone UTF-8 byte). It never
fails. A `+` is not a space.

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
== 0`), return `[a, b)`. Otherwise let `i` be the first index `>= a` of `&`; if it exists and `i < b`,
return `[a, i)`; else `[a, b)`.

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

**entropy(u)**: let `n` be the length of `u` in units. Walk `u` by code point (an astral character
or a surrogate pair is one symbol; a lone surrogate is one symbol); keep a count per symbol, symbols in
order of first occurrence. `H = 0`; for each symbol in that order: `p = count / n` (the divisor is the
length in **units**, which is larger than the number of symbols when astral characters are present), `H
= H - p * log2(p)`. IEEE 754 double arithmetic, that summation order. The empty string has entropy 0.
See section 15 about the exact comparison.

### 5.5 Trivial values and stand-ins

`isTrivialValue(raw)` (`trivial` in `algorithms.json`): `v = lower(trim(raw))`. True when `v` is in
`words` (`undefined`, `null`, `changeme`, `example`, `placeholder`, `password`, `secret`, `token`); or `v`
is non-empty and every unit equals one `maskChars` character (`x` or `*`, so `xxxx` and `****`); or `v`
has length at least 2, starts with the first and ends with the second of a `wrappers` pair (`<` `>`,
`{` `}`), and every unit between them is in `wrapperInner` (any unit that is not a line terminator:
U+000A, U+000D, U+2028, U+2029). (The wrapper test is the JavaScript `^<.*>$`.)

`isDocPlaceholder(raw)`: `v = lower(trim(raw))`. True when `v` starts with one of `prefixes`
(`your`, `my`, `the`, `replace`, `insert`, `example`, `dummy`, `sample`) followed by a unit in `separator`
(`_` or `-`), or ends with one of `suffixes` (`here`) preceded by a unit in `separator`. (`your_api_key_here`,
`REPLACE_ME_TOKEN`.)

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

The default **skip keys** are `type` and `id` (`structuralSkipKeys`): a primitive value under such a key is
kept byte for byte and never scanned; containers under them are walked.

## 7. Placeholders, hits and splicing

**Placeholder grammar** (`patterns.placeholder`): `[REDACTED` then optionally `:` rule `[^\[\]:WS]+` and
optionally `:` suffix `[^\[\]]*`, then `]`. So `[REDACTED]`, `[REDACTED:rule]` and
`[REDACTED:rule:suffix]` are placeholders. `placeholderEndAt(text, i)` is the end of the longest such
placeholder that starts exactly at `i` (the grammar has one match length per start), or `-1`.
`literalSegments(text)` is `text` split by every (non-overlapping, left to right) placeholder; it has
one more element than there are placeholders; empty elements are kept.

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
  give the same placeholder text): the later value replaces the earlier one and the key keeps the earlier
  position.
- **Numbers.** A number under a key whose verdict is `any` is replaced as a unit by `[REDACTED:key-context]`.
  Every other number is untouched and written back as it was parsed. (A number's digits are never
  scanned. Numbers beyond double precision and `-0` are out of the differential corpus; TypeScript
  parses to doubles.)
- `null` and booleans are untouched. The empty string is untouched.
- **Strings** are scanned as texts (4) and a string under a secret key is replaced whole (section 6 and 9).
- **Keys** are redacted: a key of length from 8 up to 4096 is scanned with the standard rules (`detect`)
  and spliced when it holds a secret (it can hold one, e.g. `{"password=hunter2xx": 1}`); a shorter key
  cannot match and a longer one is left as it is in `compat` (strict: section 9).
- Non-JSON values (`NaN`, infinities, functions, symbols, dates, class instances, cycles) are out of
  contract. TypeScript handles them as section 13 says; other languages MAY reject them.

## 9. Tiers and modes

**Tiers**:

- `standard`: the rules of section 4.
- `full`: the standard rules, plus the upstream secretlint preset (`algorithms.json` `upstream`: the
  preset `@secretlint/secretlint-rule-preset-recommend` 13.0.4 without `filter-comments`, AWS ID scanning
  on), merged with the standard hits. The upstream rules are specified in `INVENTORY.md`, not yet in this
  document (a later slice ports them). **Until then only the TypeScript implementation has the full tier;
  another implementation's `full` equals `standard`**, and the vectors with different `expectedSync` and
  `expectedAsync` are the backlog. The upstream scanners see only the first `full.scanCap` (2,000,000)
  units of a text, in windows of `full.scanWindow` (100,000) units that overlap by `full.scanOverlap`
  (10,240) (stride = window minus overlap, last window ends at the cap); the standard rules always see
  the whole text. A text longer than the cap is reported by the event `redaction.scan.capped`.

**Entry points** (TypeScript names; the contract is language neutral): redact a text, redact a JSON
value; each in the `standard` tier (the sync entry) and the `full` tier (the async entry).

**Modes**:

- `compat` (TypeScript default; reproduces v0.2.0). The standard tier fails closed. The full tier fails
  open: when its scanners fail it falls back to the standard rules, and a text beyond the scan cap is
  scanned by the standard rules only.
- `strict` (Python and Go default; an option in TypeScript). **No path returns text that was not scanned.**
  Any internal error, cap or limit gives an error placeholder or `[REDACTED:size-limit]` for the unscanned
  remainder.

### 9.1 Text, standard tier

`redactText(text, maxChars)` returns `(text, hits)`:

1. If `length > maxChars` (default `sync.maxChars`, 4,000,000): return `[REDACTED:size-limit]` with the hit
   `(size-limit, 0, length)`.
2. If `length < 8`: return the text and no hits.
3. `hits = detect(text)`; return `splice(text, hits)` and `hits` (already merged).
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
6. An object: for each key in contract order: if `nodes <= 0`: set `out[key] = limit(size-limit)` (the key as
   it was) and stop. Else `outKey` = the key redacted (section 8, with its hits appended to `hits`). If the
   key is a skip key and the value is a primitive: `nodes -= 1`, `out[outKey] = value` unchanged. Else
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
- Keys count against `chars` (their length) too. A key longer than `sync.maxKeyChars` (4096) or longer than
  the remaining `chars` empties the budget and is replaced by `[REDACTED:size-limit]`.
- When `nodes` runs out inside a container, the rest of the container is **collapsed**: an array gets one
  more element `[REDACTED:size-limit]`; an object gets one entry whose key and value are both
  `[REDACTED:size-limit]` (the key of the first unscanned entry is raw text and is not returned). The
  container is then complete.
- A leaf scan that fails gives `[REDACTED:redaction-failed]` for that leaf.
- Skip keys keep their meaning: a primitive under `type` or `id` is the caller's declared exemption and is
  returned unchanged. (This is the one way strict returns unscanned text; callers who want none pass an
  empty skip set.)

Everything else (order, verdicts, number handling, key redaction) is as in 9.2.

### 9.4 Full tier

- `compat`: text: `detect` is the upstream scanners over the first `scanCap` units (windowed) plus `detect`
  over the whole text, merged; splice. A detector failure emits the event `redaction.detect.failed` with the
  error class only, then returns the result of `detect` alone, or `[REDACTED:error]` with the hit `(error,
  0, 0)` if that fails too. JSON: each string leaf is a text of this kind; keys use the sync key redaction;
  no depth, node or character limit (a TypeScript behaviour kept for compatibility).
- `strict`: text: as `compat`, except that a detector failure returns `[REDACTED:error]` (no fallback), and
  the units beyond `scanCap` are replaced by `[REDACTED:size-limit]` (the hit `(size-limit, cap, length)` is
  merged with any hit it touches). JSON: the strict walk of 9.3 with each leaf scanned by this text rule.

## 10. ReDoS rules

1. Every pattern passes `recheck` (the npm package `recheck`, a version released at least 7 days ago,
   pinned exactly) with status `safe`. Anything else fails the lint.
2. The grammar of section 2 bans nested quantifiers and unbounded lazy quantifiers, and bounds lazy
   quantifiers to 64.
3. An unbounded quantifier whose class overlaps the token that follows it needs a disjoint required literal
   after it (a rule of design; `recheck` and the scaling test enforce it).
4. Work per candidate is bounded or linear; a rule restarts a failed scan so that no unit is the start of
   more than a bounded number of attempts (`restart at matchStart + 1` only where the attempt did bounded
   work; `restart at the start of the rejected value` where it is linear).
5. `tools/lint-spec` runs a **scaling test**: generated attack strings (each unit of a list that holds
   unterminated quotes, repeated keywords of the key lists, `a-` runs, whitespace runs, escape runs,
   percent triples, PEM headers, key-format prefixes) are repeated to 100 KB and to 1 MB and run through every
   pattern in JavaScript and in Python. The time at 1 MB must not exceed 30 times the time at 100 KB (floor 10
   ms) and 3 s absolute. Each run is a subprocess under an external deadline.
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

Each language package embeds a copy of `rules.json`, `keys.json`, `algorithms.json` and a generated hash
constant:

- `hash = SHA-256( for name in [rules.json, keys.json, algorithms.json]: name + NUL + bytes + NUL )`, hex,
  lower case, where NUL is the byte 0.
- At import/initialisation the package computes the hash of its embedded copy and compares it to the
  constant. A difference, an unsupported `specVersion`, or an empty rule set (no pipeline entries or no
  `secretWords`) is a fatal error and the package MUST NOT process any input.
- `tools/sync-spec` copies the data files and `vectors/` into each package and writes the constants;
  `tools/sync-spec --check` fails when a copy or a constant is out of date. It runs in CI and, on the tagged
  commit, in the release workflow.
- Error messages for these failures name the failure, never the data.

## 13. TypeScript extensions

These exist for compatibility with v0.2.0 and never change what is detected:

- Async signatures and `bigint` values (a `bigint` counts as a number).
- `restoreRedacted(redacted, stored)` and its options (restores values behind placeholders from a stored copy).
- The 0.1.1 `last4` placeholder `[REDACTED:<rule>:<last4>]` for matches of at least 16 units (`opts.last4`);
  brackets in the last four units are replaced by `*`.
- `CREDENTIAL_KEY_RE` (the 0.1.1 substring matcher, `keys.json` `tsExtensions`), `STRUCTURAL_SKIP_KEYS`.
- Input shapes outside JSON in `compat`: `Date` is returned as is; typed arrays and buffers become
  `[REDACTED:size-limit]`; an `Error` is read as `{name, message, stack}`; an object with `toJSON` as its
  result; a cycle becomes `[REDACTED:circular]`; a non-string text is turned into a string.
- `detect` override, `onEvent` callback, `skipKeys` option.

## 14. Conformance vectors

`vectors/*.json`: `{ "description", "cases": [ ... ] }`. A case has `name`, `input` (or `inputGen`), an
optional `mode` (`compat` default, `strict`) and `opts` (`maxChars`, `maxDepth`, `maxNodes`), and either
`expected` (both tiers give the same output) or `expectedSync` and `expectedAsync` (the full tier finds more).
`inputGen` and `expectedGenSync` / `expectedGenAsync` give a long string as `{ "parts": [[unit, times], ...] }`,
the concatenation of each unit repeated. A string input runs through the text entry point, any other JSON
value through the JSON entry point. The output (a string or a JSON value) must equal the expected value
exactly; for JSON, object key order is compared as the contract order. Field names are fixed (consumers
read `expectedSync` / `expectedAsync`). Every vector must also be idempotent (redacting the expected output
gives the same output).

The vectors cross every cap: text longer than `maxChars`, depth and node limits, leaf and key size limits,
the scan cap and the window overlap of the full tier. `corpus/` holds the seeded differential corpus
generator's recorded outputs for the TypeScript reference (`golden-*.json`); a differential job runs the
same seeded corpus through every implementation.

## 15. Known portability risks

- **Entropy comparison**: `log2` and the summation are floating point. Engines may differ in the last unit
  of precision; a value whose entropy lies within about 1e-9 of 3.4 can decide differently. The vectors and
  the corpus avoid that band; an implementation SHOULD compute with IEEE 754 doubles in the order of 5.4.
- **Percent decoding**: UTF-8 decoding of `%XX` runs must reject exactly what ECMAScript
  `decodeURIComponent` rejects (overlong forms, surrogate code points, truncated sequences); then the value
  is left whole (4.9).
- **Unicode letter guard** (upstream rules, later slice): needs one pinned Unicode version across languages.
- **Unit counting** (section 1): the most likely source of drift (astral characters inside values and keys,
  lone surrogates, invalid UTF-8 in Go).
- **Numbers** beyond double precision are not in the corpus.
