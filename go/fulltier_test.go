package redaction

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

const npmToken = "npm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// spaced is a text of `length` spaces with the npm token at unit `at` and `front` before it.
func spaced(length int, at int, front string) string {
	text := []byte(strings.Repeat(" ", length))
	if front != "" {
		text[at-1] = front[0]
	}
	copy(text[at:], npmToken)
	return string(text)
}

func unitLength(s string) int {
	return len(utf16.Encode([]rune(s)))
}

// placeholderAt is the unit index of the first `[REDACTED:` of the text, or -1.
func placeholderAt(s string) int {
	at := strings.Index(s, "[REDACTED:")
	if at < 0 {
		return -1
	}
	return unitLength(s[:at])
}

func TestLetterTable(t *testing.T) {
	table := theEngine.letters
	letters := []rune{'A', 'Z', 'a', 'z', 0xAA, 0xB5, 0xE9, 0x3A9, 0x2B0, 0x1C5, 0x6FA, 0x6FF}
	letters = append(letters, 0x1D400, 0x3400, 0x20000, 0x2FA1D)
	for _, r := range letters {
		if !table.isLetter(uint32(r)) {
			t.Errorf("U+%04X should be a letter", r)
		}
	}
	others := []rune{
		'0', '9', ' ', '_', '-', '.', 0xA0, 0xB2, 0x663, 0x6F8, 0x2028, 0xFEFF,
		0x1F600, 0xD7FF, 0xE000, 0x10FFFF,
	}
	for _, r := range others {
		if table.isLetter(uint32(r)) {
			t.Errorf("U+%04X should not be a letter", r)
		}
	}
}

func TestLetterGuardReadsCodePointsBeforeAPosition(t *testing.T) {
	table := theEngine.letters
	cases := []struct {
		name  string
		units []uint16
		at    int
		want  bool
	}{
		{"start of the text", decodeUTF8("a"), 0, true},
		{"ASCII letter", decodeUTF8("ax"), 1, false},
		{"digit", decodeUTF8("1x"), 1, true},
		{"astral letter is one code point", decodeUTF8("\U0001D400x"), 2, false},
		{"astral emoji is not a letter", decodeUTF8("\U0001F600x"), 2, true},
		{"low surrogate of a letter is not a letter by itself", []uint16{0xDC00, 'x'}, 1, true},
		{"lone high surrogate", []uint16{0xD835, 'x'}, 1, true},
		{"lone low surrogate", []uint16{'a', 0xDC00, 'x'}, 2, true},
		{"low surrogate after a non-surrogate", []uint16{'a', 0xDC00}, 2, true},
	}
	for _, c := range cases {
		if got := table.passesGuard(c.units, c.at); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMalformedLetterTablesAreRefused(t *testing.T) {
	bad := []string{
		"", "41-5a,", "5a-41", "zz", "41-5a,5a-61", "41-5a,5b-61", "61-7a,41-5a", "41-110000", "41--5a",
	}
	for _, encoded := range bad {
		if _, err := parseLetters(encoded); err != errBadLetters {
			t.Errorf("%q: got %v", encoded, err)
		}
	}
	if _, err := parseLetters("41-5a,61-7a,aa"); err != nil {
		t.Errorf("a well-formed table was refused: %v", err)
	}
}

func units(s string) []uint16 {
	return decodeUTF8(s)
}

func TestBase64JSON(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{"object", "eyJhIjoxfQ==", true},
		{"object without padding", "eyJhIjoxfQ", true},
		{"array", "WzEsMl0=", true},
		{"empty object", "e30=", true},
		{"empty array", "W10=", true},
		{"nested", "eyJhIjpbMSx7ImIiOm51bGx9XX0=", true},
		{"a scalar is not a container", "MTIz", false},
		{"a string is not a container", "ImEi", false},
		{"trailing garbage", "eyJhIjoxfXg=", false},
		{"trailing comma", "eyJhIjoxLH0=", false},
		{"length 1 modulo 4", "eyJhI", false},
		{"padding in the middle", "ey==Ijox", false},
		{"three padding units", "eyJhIjoxfQ===", false},
		{"outside the alphabet", "eyJh-joxfQ==", false},
		{"not JSON", "aGVsbG8gd29ybGQ=", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := isBase64JSON(units(c.token)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestJSONContainerCheckSyntax(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{` {"a" : [1, -2.5e+3, true, false, null, "x\n\u00e9\/"] } `, true},
		{`[[],{},[[]],{"a":{}}]`, true},
		{"[1,\t2,\r\n3]", true},
		{`{"a":01}`, false},
		{`{"a":1.}`, false},
		{`{"a":.5}`, false},
		{`{"a":1e}`, false},
		{`{"a":"\x"}`, false},
		{`{"a":"\u12G4"}`, false},
		{"{\"a\":\"line\nbreak\"}", false},
		{`{"a":tru}`, false},
		{`{"a":NaN}`, false},
		{`{a:1}`, false},
		{`{"a" 1}`, false},
		{`{"a":1,}`, false},
		{`[1 2]`, false},
		{`[1,]`, false},
		{`[`, false},
		{`{"a":[1,2}`, false},
		{`{}{}`, false},
		{``, false},
		{`"a"`, false},
		{`1`, false},
	}
	for _, c := range cases {
		if got := isJSONContainer([]byte(c.text)); got != c.want {
			t.Errorf("%q: got %v, want %v", c.text, got, c.want)
		}
	}
	deep := strings.Repeat("[", 200_000) + strings.Repeat("]", 200_000)
	if !isJSONContainer([]byte(deep)) {
		t.Error("deep nesting is refused: the check has a depth limit")
	}
	if isJSONContainer([]byte(deep[:len(deep)-1])) {
		t.Error("an unclosed deep container is accepted")
	}
}

func TestFullTierFindsWhatTheStandardTierDoesNot(t *testing.T) {
	standard, standardResult := RedactText(npmToken, Options{})
	full, fullResult := RedactText(npmToken, Options{Tier: TierFull})
	if standard != npmToken || len(standardResult.Hits) != 0 {
		t.Fatalf("the standard tier changed the token: %q", standard)
	}
	if full != "[REDACTED:npm]" || len(fullResult.Hits) != 1 || fullResult.Hits[0] != (RuleCount{"npm", 1}) {
		t.Fatalf("got %q with %+v", full, fullResult)
	}
}

func TestFullTierWindowsAndTheScanCap(t *testing.T) {
	cases := []struct {
		name     string
		text     string
		mode     Mode
		wantAt   int // the unit of the first placeholder, -1 for none
		wantUnit int // the length of the output in units
	}{
		// A letter before a window start is not seen by that window: the second window finds the token.
		{"window 2 sees a start the first window refuses", spaced(100_001, 89_760, "x"), Compat, 89_760,
			99_975},
		{"a letter inside both windows refuses", spaced(100_001, 89_761, "x"), Compat, -1, 100_001},
		{"a token across the first window end", spaced(150_000, 99_980, ""), Compat, 99_980, 149_974},
		{"across the window end, behind a letter", spaced(150_000, 99_990, "x"), Compat, -1, 150_000},
		{"inside the cap", spaced(2_000_100, 1_999_900, ""), Compat, 1_999_900, 2_000_074},
		{"cut by the cap, compat", spaced(2_000_100, 1_999_990, ""), Compat, -1, 2_000_100},
		{"beyond the cap, compat", spaced(2_000_100, 2_000_050, ""), Compat, -1, 2_000_100},
		{"exactly the cap", spaced(2_000_000, 1_999_960, ""), Compat, 1_999_960, 1_999_974},
		{"cut by the cap, strict", spaced(2_000_100, 1_999_990, ""), Strict, 2_000_000, 2_000_021},
		{"beyond the cap, strict", spaced(2_000_100, 2_000_050, ""), Strict, 2_000_000, 2_000_021},
		{"inside the cap, strict", spaced(2_000_100, 1_999_900, ""), Strict, 1_999_900, 1_999_995},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _ := RedactText(c.text, Options{Tier: TierFull, Mode: c.mode})
			if got := placeholderAt(out); got != c.wantAt || unitLength(out) != c.wantUnit {
				t.Fatalf("first placeholder at %d, %d units; want %d, %d", got, unitLength(out), c.wantAt,
					c.wantUnit)
			}
			if c.mode == Strict && !strings.HasSuffix(out, "[REDACTED:size-limit]") {
				t.Fatal("the units beyond the cap are not replaced")
			}
		})
	}
}

// A hit that reaches the scan cap merges with the size-limit hit that follows it and keeps its own
// rule id and count; the call still reports that units beyond the cap were not scanned.
func TestFullTierStrictReportsTheCapWhenTheSizeLimitHitIsMerged(t *testing.T) {
	text := strings.Repeat(" ", 1_999_960) + npmToken + strings.Repeat("b", 1000)
	out, result := RedactText(text, Options{Tier: TierFull, Mode: Strict})
	if out != strings.Repeat(" ", 1_999_960)+"[REDACTED:npm]" {
		t.Fatalf("got %d units, placeholder at %d", unitLength(out), placeholderAt(out))
	}
	if result.Err != "size-limit" || len(result.Hits) != 1 || result.Hits[0] != (RuleCount{"npm", 1}) {
		t.Fatalf("got %+v", result)
	}
	_, plain := RedactText(strings.Repeat(" ", 1_999_990)+npmToken, Options{Tier: TierFull, Mode: Strict})
	if plain.Err != "size-limit" || len(plain.Hits) != 1 || plain.Hits[0].RuleID != "size-limit" {
		t.Fatalf("an unmerged size-limit hit: got %+v", plain)
	}
	_, within := RedactText(strings.Repeat(" ", 1_999_900)+npmToken, Options{Tier: TierFull, Mode: Compat})
	if within.Err != "" {
		t.Fatalf("compat reported a failure: %+v", within)
	}
}

func TestFullTierCompatHasNoLimitsAndStrictDoes(t *testing.T) {
	long := strings.Repeat("a", 50) + " " + npmToken
	compat, _ := RedactText(long, Options{Tier: TierFull, Mode: Compat})
	if !strings.HasSuffix(compat, "[REDACTED:npm]") {
		t.Fatalf("compat applied a limit: %q", compat)
	}
	strict, result := RedactText(long, Options{Tier: TierFull, Mode: Strict, MaxChars: Limit(10)})
	if strict != "[REDACTED:size-limit]" || result.Err != "size-limit" {
		t.Fatalf("got %q with %+v", strict, result)
	}
	nested := []byte(`{"a":{"b":"` + npmToken + `"}}`)
	out, _, err := RedactJSON(nested, Options{Tier: TierFull, Mode: Compat})
	if err != nil || string(out) != `{"a":{"b":"[REDACTED:npm]"}}` {
		t.Fatalf("compat without limits: %s, %v", out, err)
	}
	out, _, _ = RedactJSON(nested, Options{Tier: TierFull, Mode: Strict, MaxDepth: Limit(1)})
	if string(out) != `{"a":"[REDACTED:depth-limit]"}` {
		t.Fatalf("strict ignored the depth limit: %s", out)
	}
}

func TestFullTierCompatRefusesExplicitLimits(t *testing.T) {
	const marker = "Zq9LEAKcheck77xQ4mN2vB8kR5tY1wE6"
	limited := map[string]Options{
		"MaxChars":      {Tier: TierFull, Mode: Compat, MaxChars: Limit(10)},
		"MaxDepth":      {Tier: TierFull, Mode: Compat, MaxDepth: Limit(5)},
		"MaxNodes":      {Tier: TierFull, Mode: Compat, MaxNodes: Limit(5)},
		"a limit of 0":  {Tier: TierFull, Mode: Compat, MaxNodes: Limit(0)},
		"an other tier": {Tier: Tier(7), Mode: Compat, MaxChars: Limit(10)},
		"a negative":    {Tier: Tier(-1), Mode: Compat, MaxChars: Limit(10)},
	}
	for name, opts := range limited {
		text, result := RedactText("password="+marker, opts)
		if text != "[REDACTED:error]" || result.Err != "invalid-options" ||
			len(result.Hits) != 1 || result.Hits[0] != (RuleCount{"error", 1}) {
			t.Errorf("%s: RedactText got %q, %+v", name, text, result)
		}
		out, jsonResult, err := RedactJSON([]byte(`{"password":"`+marker+`"}`), opts)
		isRefused := err == ErrInvalidOptions && string(out) == `"[REDACTED:error]"`
		if !isRefused || jsonResult.Err != "invalid-options" {
			t.Errorf("%s: RedactJSON got %q, %+v, %v", name, out, jsonResult, err)
		}
		if strings.Contains(string(out), marker) || strings.Contains(text, marker) {
			t.Errorf("%s: the input is in the output", name)
		}
	}
	for name, opts := range map[string]Options{
		"strict full": {
			Tier: TierFull, Mode: Strict, MaxChars: Limit(1000), MaxDepth: Limit(5), MaxNodes: Limit(5),
		},
		"standard compat":  {Mode: Compat, MaxChars: Limit(1000)},
		"standard strict":  {MaxChars: Limit(1000)},
		"compat full none": {Tier: TierFull, Mode: Compat},
	} {
		text, result := RedactText("password="+marker, opts)
		if text != "password=[REDACTED:generic-keyword]" || result.Err != "" {
			t.Errorf("%s: got %q, %+v", name, text, result)
		}
	}
}

func TestAnOutOfRangeTierIsTheFullTier(t *testing.T) {
	for _, tier := range []Tier{2, 7, -1} {
		out, _ := RedactText(npmToken, Options{Tier: tier})
		if out != "[REDACTED:npm]" {
			t.Errorf("tier %d: got %q", tier, out)
		}
	}
}

func TestFullTierJSONScansValuesAndKeys(t *testing.T) {
	input := `{"` + npmToken + `":"` + npmToken + `","list":["` + npmToken + `","x"],"type":"` + npmToken +
		`","id":"` + npmToken + `","n":1}`
	compat := `{"[REDACTED:npm]":"[REDACTED:npm]","list":["[REDACTED:npm]","x"],"type":"` + npmToken +
		`","id":"` + npmToken + `","n":1}`
	strict := `{"[REDACTED:npm]":"[REDACTED:npm]","list":["[REDACTED:npm]","x"],"type":"[REDACTED:npm]",` +
		`"id":"[REDACTED:npm]","n":1}`
	for mode, want := range map[Mode]string{Compat: compat, Strict: strict} {
		out, result, err := RedactJSON([]byte(input), Options{Tier: TierFull, Mode: mode})
		if err != nil || string(out) != want {
			t.Errorf("mode %d:\n got  %s\n want %s", mode, out, want)
		}
		if got := countsOf(result)["npm"]; got < 3 {
			t.Errorf("mode %d: %d npm hits, want the key among them", mode, got)
		}
	}
	// The standard tier does not know the format: the key stays.
	out, _, _ := RedactJSON([]byte(`{"`+npmToken+`":1}`), Options{})
	if string(out) != `{"`+npmToken+`":1}` {
		t.Errorf("the standard tier changed the key: %s", out)
	}
}

// slackToken and onePasswordToken are tokens of full-tier rules of other kinds than `token`.
const (
	slackToken       = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
	onePasswordToken = "ops_eyJmYWtlIjoibm90LWEtcmVhbC1jcmVkZW50aWFsIiwicGFkZGluZyI6IkFBQUFBQUFB" +
		"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ=="
)

func TestFullTierKeysThatAreTokensAreReplaced(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want string
	}{
		{"npm", npmToken, "[REDACTED:npm]"},
		{"Slack", slackToken, "[REDACTED:slack]"},
		{"a token inside a longer key", "prefix " + npmToken + " suffix", "prefix [REDACTED:npm] suffix"},
		{"a key under 8 units is not scanned", "ghp_abcd", "ghp_abcd"},
	}
	for _, c := range cases {
		for _, mode := range []Mode{Compat, Strict} {
			out, _, err := RedactJSON([]byte(`{"`+c.key+`":1}`), Options{Tier: TierFull, Mode: mode})
			if err != nil || string(out) != `{"`+c.want+`":1}` {
				t.Errorf("%s, mode %d: got %s, %v", c.name, mode, out, err)
			}
		}
	}
	// A 1Password token is only a token when its body is base64 of a JSON object.
	out, _, _ := RedactJSON([]byte(`{"`+onePasswordToken+`":1}`), Options{Tier: TierFull})
	if string(out) != `{"[REDACTED:1password]":1}` {
		t.Errorf("a 1Password token as a key: %s", out)
	}
}

func TestFullTierKeysThatCollideAfterRedactionKeepTheFirstPosition(t *testing.T) {
	other := "npm_" + strings.Repeat("B", 36)
	input := `{"` + npmToken + `":1,"mid":2,"` + other + `":3}`
	want := `{"[REDACTED:npm]":3,"mid":2}`
	for _, mode := range []Mode{Compat, Strict} {
		out, _, err := RedactJSON([]byte(input), Options{Tier: TierFull, Mode: mode})
		if err != nil || string(out) != want {
			t.Errorf("mode %d: got %s, %v", mode, out, err)
		}
	}
}

func TestFullTierKeyLimitsAreTheStandardOnes(t *testing.T) {
	long := strings.Repeat("a", 4097)
	compat, _, _ := RedactJSON([]byte(`{"`+long+`":1}`), Options{Tier: TierFull, Mode: Compat})
	if string(compat) != `{"`+long+`":1}` {
		t.Errorf("compat changed an over-long key")
	}
	strict, _, _ := RedactJSON([]byte(`{"`+long+`":1}`), Options{Tier: TierFull, Mode: Strict})
	if string(strict) != `{"[REDACTED:size-limit]":1}` {
		t.Errorf("strict did not replace an over-long key: %s", strict)
	}
}

func TestFullTierInvalidJSONIsRedactedAsAFullTierText(t *testing.T) {
	out, result, err := RedactJSON([]byte(npmToken+" {"), Options{Tier: TierFull})
	if err != ErrInvalidJSON || string(out) != "[REDACTED:npm] {" || result.Hits[0].RuleID != "npm" {
		t.Fatalf("got %q, %+v, %v", out, result, err)
	}
}

func TestFullTierConnectionStrings(t *testing.T) {
	cases := map[string]string{
		"postgres://admin:s3cr3tPass@db.example.com:5432/app": "[REDACTED:database-connection-string]",
		"See https://user:hunter2xx@example.com/x and mongodb://svc:Zq9abcdef@host.test/db?x=1": "See " +
			"[REDACTED:basicauth]/x and [REDACTED:database-connection-string]",
	}
	for input, want := range cases {
		if got, _ := RedactText(input, Options{Tier: TierFull, Mode: Compat}); got != want {
			t.Errorf("%q: got %q, want %q", input, got, want)
		}
	}
}

// panicScanner is a rule that fails.
type panicScanner struct{}

func (panicScanner) scan(*text) []span {
	panic("a rule failed")
}

// brokenEngine is a copy of the engine whose full-tier rules (and, if asked, the standard rules) fail.
func brokenEngine(standardFails bool) *engine {
	broken := *theEngine
	broken.full = []pipelineEntry{{id: "broken", scanner: panicScanner{}}}
	if standardFails {
		broken.pipeline = []pipelineEntry{{id: "broken", scanner: panicScanner{}}}
	}
	return &broken
}

func failureCase(e *engine, mode scanMode, input string) (string, Result) {
	rec := newRecorder(e)
	out := e.redactTextSafely(input, mode, rec)
	return out, rec.result()
}

func TestFullTierFailureHandling(t *testing.T) {
	const input = "password=Zq9abcDEF123ghi_x and more text"
	compat := scanMode{tier: TierFull, maxChars: unbounded}
	strict := scanMode{tier: TierFull, strict: true, maxChars: unbounded}
	t.Run("compat falls back to the standard rules", func(t *testing.T) {
		out, result := failureCase(brokenEngine(false), compat, input)
		if out != "password=[REDACTED:generic-keyword] and more text" || result.Err != "" {
			t.Fatalf("got %q with %+v", out, result)
		}
	})
	t.Run("compat gives the error placeholder when the standard rules fail too", func(t *testing.T) {
		out, result := failureCase(brokenEngine(true), compat, input)
		if out != "[REDACTED:error]" || result.Err != "error" || result.Hits[0] != (RuleCount{"error", 1}) {
			t.Fatalf("got %q with %+v", out, result)
		}
	})
	t.Run("strict has no fallback", func(t *testing.T) {
		out, result := failureCase(brokenEngine(false), strict, input)
		if out != "[REDACTED:error]" || result.Err != "error" {
			t.Fatalf("got %q with %+v", out, result)
		}
	})
	t.Run("a failing leaf is replaced and the rest of the document is kept", func(t *testing.T) {
		e := brokenEngine(false)
		rec := newRecorder(e)
		everything := parseLimits{nodes: unbounded, depth: unbounded, chars: unbounded}
		root, err := parseJSON([]byte(`{"a":"`+input+`","n":1}`), everything)
		if err != nil {
			t.Fatal(err)
		}
		opts := Options{Tier: TierFull, Mode: Strict}
		lim := e.limits(opts)
		out := string(marshal(e.walkSafely(root, opts, lim, rec)))
		if out != `{"a":"[REDACTED:error]","n":1}` || rec.result().Err != "error" {
			t.Fatalf("got %s with %+v", out, rec.result())
		}
	})
}

func TestFullTierResultsNameSpecIDsOnly(t *testing.T) {
	text := npmToken + " ghp_" + strings.Repeat("b", 36) + " password=Zq9abcDEF123ghi_x"
	out, result := RedactText(text, Options{Tier: TierFull})
	if strings.Contains(out, "npm_") || strings.Contains(out, "ghp_") {
		t.Fatalf("a token survives: %q", out)
	}
	want := []RuleCount{{"npm", 1}, {"github", 1}, {"generic-keyword", 1}}
	if len(result.Hits) != len(want) {
		t.Fatalf("got %+v", result.Hits)
	}
	for i := range want {
		if result.Hits[i] != want[i] {
			t.Fatalf("got %+v, want %+v", result.Hits, want)
		}
	}
	for _, entry := range result.Hits {
		if strings.Contains(entry.RuleID, "@") || strings.Contains(entry.RuleID, "secretlint") {
			t.Fatalf("a rule id carries the legacy prefix: %q", entry.RuleID)
		}
	}
}

func TestFullTierSpecProblemsAreRefused(t *testing.T) {
	files := embeddedFiles(t)
	rules := string(files.rules)
	algorithms := string(files.algorithms)
	build := func(rulesText string, algorithmsText string) error {
		changed := files
		changed.rules, changed.algorithms = []byte(rulesText), []byte(algorithmsText)
		spec, err := decodeSpec(changed)
		if err != nil {
			return err
		}
		_, err = newEngine(spec)
		return err
	}
	if err := build(rules, algorithms); err != nil {
		t.Fatalf("the unchanged spec was refused: %v", err)
	}
	cases := []struct {
		name  string
		rules string
		algos string
		want  error
	}{
		{"an unknown check", strings.Replace(rules, `"base64-json"`, `"nope"`, 1), algorithms,
			errUnknownCheck},
		{"an unknown full-tier kind", strings.Replace(rules, `"kind": "sendgrid-key"`, `"kind": "bogus"`, 1),
			algorithms, nil},
		{"a standard kind in the full list",
			strings.Replace(rules, `"kind": "dash-chain"`, `"kind": "cookie-lines"`, 1), algorithms, nil},
		{"no letter table", rules, strings.Replace(algorithms, `"ranges": "`, `"ranges": "", "was": "`, 1),
			errSpecRejected},
		{"a window that is not larger than its overlap", rules,
			strings.Replace(algorithms, `"scanOverlap": 10240`, `"scanOverlap": 100000`, 1), errSpecRejected},
		{"a cap below the window", rules,
			strings.Replace(algorithms, `"scanCap": 2000000`, `"scanCap": 50000`, 1), errSpecRejected},
	}
	for _, c := range cases {
		err := build(c.rules, c.algos)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
	emptied := strings.Replace(rules, `"full": [`, `"full": [], "unused": [`, 1)
	if err := build(emptied, algorithms); !errors.Is(err, errSpecRejected) {
		t.Errorf("an empty full tier: got %v", err)
	}
}

func TestFullTierResultAndErrorsHoldNoMatchedText(t *testing.T) {
	const body = "Zq9LEAKcheck77xQ4mN2vB8kR5tY1wE6"
	inputs := []string{
		"npm_" + body + "AAAA",
		"postgres://svc:" + injectedMarker + "@db.test/app",
		"ghp_" + body + "abcd",
		strings.Repeat("a", 40) + " glpat-" + body,
	}
	for _, input := range inputs {
		for _, mode := range []Mode{Compat, Strict} {
			out, result := RedactText(input, Options{Tier: TierFull, Mode: mode})
			if strings.Contains(out, body) || strings.Contains(out, injectedMarker) {
				t.Fatalf("mode %d: a secret survives in %q", mode, out)
			}
			if result.Err != "" || len(result.Hits) == 0 {
				t.Fatalf("mode %d: got %+v", mode, result)
			}
			for _, entry := range result.Hits {
				if strings.Contains(entry.RuleID, body) || strings.Contains(entry.RuleID, injectedMarker) {
					t.Fatalf("a rule id holds matched text: %q", entry.RuleID)
				}
			}
		}
	}
	long := strings.Repeat("a", 9) + "npm_" + body
	_, result := RedactText(long, Options{Tier: TierFull, Mode: Strict, MaxChars: Limit(8)})
	if result.Err != "size-limit" {
		t.Fatalf("got %+v", result)
	}
}
