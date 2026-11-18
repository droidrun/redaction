package redaction

import (
	"strings"
	"testing"
)

type jsonCase struct {
	name     string
	input    string
	opts     Options
	expected string
}

func runJSONCases(t *testing.T, cases []jsonCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, err := RedactJSON([]byte(c.input), c.opts)
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != c.expected {
				t.Fatalf("got %s, want %s", out, c.expected)
			}
		})
	}
}

func TestStrictNeverReturnsUnscannedText(t *testing.T) {
	longKey := strings.Repeat("a", 4097)
	runJSONCases(t, []jsonCase{
		{
			"skip key string is scanned",
			`{"id":"password=Zq9abcDEF123ghi_x","type":"user"}`, Options{},
			`{"id":"password=[REDACTED:generic-keyword]","type":"user"}`,
		},
		{
			"custom skip key string is scanned",
			`{"skip":"password=Zq9abcDEF123ghi_x"}`, Options{SkipKeys: []string{"skip"}},
			`{"skip":"password=[REDACTED:generic-keyword]"}`,
		},
		{
			"node limit collapses an array",
			`["a","b","c","d"]`, Options{MaxNodes: 3},
			`["a","b","[REDACTED:size-limit]"]`,
		},
		{
			"node limit collapses an object into one entry",
			`{"a":"x","b":"y","c":"z"}`, Options{MaxNodes: 2},
			`{"a":"x","[REDACTED:size-limit]":"[REDACTED:size-limit]"}`,
		},
		{
			"depth limit",
			`{"a":{"b":{"c":"x"}}}`, Options{MaxDepth: 2},
			`{"a":{"b":"[REDACTED:depth-limit]"}}`,
		},
		{
			"key over the key limit",
			`{"` + longKey + `":"x"}`, Options{},
			`{"[REDACTED:size-limit]":"[REDACTED:size-limit]"}`,
		},
		{
			"keys count against the character budget",
			`{"password":"abcdefghi","n":5,"list":["xxxxxxxxx"]}`, Options{MaxChars: 12},
			`{"password":"[REDACTED:key-context]","n":5,"[REDACTED:size-limit]":["[REDACTED:size-limit]"]}`,
		},
		{
			"a leaf that does not fit empties the budget",
			`{"a":"aaaaaaaaaaaa","b":"bbbbbbbb"}`, Options{MaxChars: 12},
			`{"a":"[REDACTED:size-limit]","[REDACTED:size-limit]":"[REDACTED:size-limit]"}`,
		},
	})
}

func TestCompatKeepsSkipKeyStrings(t *testing.T) {
	runJSONCases(t, []jsonCase{
		{
			"default skip keys",
			`{"id":"password=Zq9abcDEF123ghi_x","type":"user"}`, Options{Mode: Compat},
			`{"id":"password=Zq9abcDEF123ghi_x","type":"user"}`,
		},
		{
			"custom skip key",
			`{"skip":"password=Zq9abcDEF123ghi_x"}`, Options{Mode: Compat, SkipKeys: []string{"skip"}},
			`{"skip":"password=Zq9abcDEF123ghi_x"}`,
		},
		{
			"an empty skip list skips nothing",
			`{"id":"password=Zq9abcDEF123ghi_x"}`, Options{Mode: Compat, SkipKeys: []string{}},
			`{"id":"password=[REDACTED:generic-keyword]"}`,
		},
	})
}

func TestStrictIsTheDefaultMode(t *testing.T) {
	var zero Options
	if zero.Mode != Strict {
		t.Fatal("the zero Options value is not strict")
	}
	text, result := RedactText("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Options{MaxChars: 10})
	if text != "[REDACTED:size-limit]" || result.Err != "size-limit" {
		t.Fatalf("got %q with %q", text, result.Err)
	}
}

func TestVeryDeepInputCostsNoStack(t *testing.T) {
	const depth = 1_000_000
	input := strings.Repeat("[", depth) + strings.Repeat("]", depth)
	out, result, err := RedactJSON([]byte(input), Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("[", 64) + `"[REDACTED:depth-limit]"` + strings.Repeat("]", 64)
	if string(out) != want {
		t.Fatal("deep input is not cut at the depth limit")
	}
	if result.Err != "depth-limit" {
		t.Fatalf("Err is %q", result.Err)
	}
}

func TestResultCountsHitsPerRule(t *testing.T) {
	text := "password=Zq9abcDEF123ghi_x and Authorization: Bearer abc.def-1=xyz " +
		"and password=Zq9abcDEF123ghi_y"
	_, result := RedactText(text, Options{})
	want := []RuleCount{{"generic-keyword", 2}, {"auth-header", 1}}
	if len(result.Hits) != len(want) {
		t.Fatalf("got %v", result.Hits)
	}
	for i, entry := range want {
		if result.Hits[i] != entry {
			t.Fatalf("got %v, want %v", result.Hits, want)
		}
	}
	if result.Err != "" {
		t.Fatalf("Err is %q", result.Err)
	}
}

func TestJSONKeyOrderDuplicatesAndNumbers(t *testing.T) {
	runJSONCases(t, []jsonCase{
		{
			"integer-like keys first, ascending",
			`{"10":1,"b":2,"2":3,"a":4,"01":5}`, Options{},
			`{"2":3,"10":1,"b":2,"a":4,"01":5}`,
		},
		{
			"duplicate key: last wins, first position",
			`{"a":1,"b":2,"a":3}`, Options{},
			`{"a":3,"b":2}`,
		},
		{
			"numbers as ECMAScript writes them",
			`[1.0, 1e2, 1E+21, -0, 9007199254740993, 0.1, 1e-7, 123456789012345680000, 1.5e300]`, Options{},
			`[1,100,1e+21,0,9007199254740992,0.1,1e-7,123456789012345680000,1.5e+300]`,
		},
		{
			"numbers under secret keys",
			`{"pin":1234,"max_tokens":5,"tokens":7,"apiKey":null,"secret":true}`, Options{},
			`{"pin":"[REDACTED:key-context]","max_tokens":5,"tokens":7,"apiKey":null,"secret":true}`,
		},
		{
			"a key that holds a secret",
			`{"password=Zq9abcDEF123ghi_x":1}`, Options{},
			`{"password=[REDACTED:generic-keyword]":"[REDACTED:key-context]"}`,
		},
	})
}

func TestInvalidJSONIsAnErrorWithoutTheInput(t *testing.T) {
	inputs := []string{
		"", "{", `{"a":}`, `[1,]`, "01", `"a`, "nul", `{"a":1} x`, "\ufeff{}", `"\x"`, "[\"\n\"]",
	}
	for _, input := range inputs {
		out, _, err := RedactJSON([]byte(input), Options{})
		if err != ErrInvalidJSON || out != nil {
			t.Fatalf("%q: got %q, %v", input, out, err)
		}
	}
}
