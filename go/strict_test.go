package redaction

import (
	"reflect"
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
			`["a","b","c","d"]`, Options{MaxNodes: Limit(3)},
			`["a","b","[REDACTED:size-limit]"]`,
		},
		{
			"node limit collapses an object into one entry",
			`{"a":"x","b":"y","c":"z"}`, Options{MaxNodes: Limit(2)},
			`{"a":"x","[REDACTED:size-limit]":"[REDACTED:size-limit]"}`,
		},
		{
			"depth limit",
			`{"a":{"b":{"c":"x"}}}`, Options{MaxDepth: Limit(2)},
			`{"a":{"b":"[REDACTED:depth-limit]"}}`,
		},
		{
			"key over the key limit",
			`{"` + longKey + `":"x"}`, Options{},
			`{"[REDACTED:size-limit]":"[REDACTED:size-limit]"}`,
		},
		{
			"keys count against the character budget",
			`{"password":"abcdefghi","n":5,"list":["xxxxxxxxx"]}`, Options{MaxChars: Limit(12)},
			`{"password":"[REDACTED:key-context]","n":5,"[REDACTED:size-limit]":["[REDACTED:size-limit]"]}`,
		},
		{
			"a leaf that does not fit empties the budget",
			`{"a":"aaaaaaaaaaaa","b":"bbbbbbbb"}`, Options{MaxChars: Limit(12)},
			`{"a":"[REDACTED:size-limit]","[REDACTED:size-limit]":"[REDACTED:size-limit]"}`,
		},
	})
}

func TestExplicitZeroLimitsAreLimits(t *testing.T) {
	for _, mode := range []Mode{Strict, Compat} {
		chars := map[Mode]string{
			// both keys exceed the exhausted budget and read the same: no value is lost (L-P)
			Strict: `{"[REDACTED:size-limit]":"[REDACTED:size-limit]","[REDACTED:size-limit#2]":""}`,
			Compat: `{"x":"[REDACTED:size-limit]","y":""}`,
		}
		runJSONCases(t, []jsonCase{
			{
				"depth zero cuts the root container",
				`{"x":"visible"}`, Options{Mode: mode, MaxDepth: Limit(0)},
				`"[REDACTED:depth-limit]"`,
			},
			{
				"depth zero keeps a root primitive",
				`"visible"`, Options{Mode: mode, MaxDepth: Limit(0)},
				`"visible"`,
			},
			{
				"nodes zero cuts the root",
				`{"x":"visible"}`, Options{Mode: mode, MaxNodes: Limit(0)},
				`"[REDACTED:size-limit]"`,
			},
			{
				"chars zero cuts every non-empty leaf",
				`{"x":"visible","y":""}`, Options{Mode: mode, MaxChars: Limit(0)},
				chars[mode],
			},
		})
		text, result := RedactText("abcdefghi", Options{Mode: mode, MaxChars: Limit(0)})
		if text != "[REDACTED:size-limit]" || result.Err != "size-limit" {
			t.Fatalf("mode %v: got %q with %q", mode, text, result.Err)
		}
	}
}

func TestOmittedLimitsAreTheSpecDefaults(t *testing.T) {
	out, _, err := RedactJSON([]byte(`{"x":"visible"}`), Options{})
	if err != nil || string(out) != `{"x":"visible"}` {
		t.Fatalf("got %s, %v", out, err)
	}
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
	text, result := RedactText("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Options{MaxChars: Limit(10)})
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
			"numbers are written back as they appeared",
			`[1.0, 1e2, 1E+21, -0, 9007199254740993, 0.1, 1e-7, 123456789012345680000, 1.5e300, 1e400]`,
			Options{},
			`[1.0,1e2,1E+21,-0,9007199254740993,0.1,1e-7,123456789012345680000,1.5e300,1e400]`,
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

func TestInvalidJSONGivesTheRedactedTextAndAnError(t *testing.T) {
	cases := []struct{ input, want string }{
		{"", ""},
		{"{", "{"},
		{`{"a":1} x`, `{"a":1} x`},
		{`{"password":"` + secretValue + `" oops`, `{"password":"[REDACTED:generic-keyword]" oops`},
		{"password=" + secretValue + " {", "password=" + keyword + " {"},
		{"\xff\xfe " + "password=" + secretValue, "\ufffd\ufffd password=" + keyword},
	}
	for _, c := range cases {
		out, result, err := RedactJSON([]byte(c.input), Options{})
		if err != ErrInvalidJSON || out == nil || string(out) != c.want {
			t.Fatalf("%q: got %q, %v", c.input, out, err)
		}
		_, textResult := RedactText(c.input, Options{})
		if !reflect.DeepEqual(result, textResult) {
			t.Fatalf("%q: result %+v differs from the text result %+v", c.input, result, textResult)
		}
	}
}

func TestInvalidJSONObeysTheLimits(t *testing.T) {
	huge := []byte(strings.Repeat("[", 10_000_000))
	out, result, err := RedactJSON(huge, Options{})
	if err != ErrInvalidJSON || string(out) != "[REDACTED:size-limit]" || result.Err != "size-limit" {
		t.Fatalf("got %q, %+v, %v", out, result, err)
	}
}

func TestInvalidJSONNeverReturnsTheInput(t *testing.T) {
	inputs := []string{
		`{"token":"` + injectedMarker + `"`, injectedMarker + " token",
		`[1,2,"password=` + injectedMarker,
	}
	for _, input := range inputs {
		out, _, err := RedactJSON([]byte(input), Options{})
		if err != ErrInvalidJSON {
			t.Fatal(err)
		}
		if strings.Contains(string(out), injectedMarker) && !strings.HasPrefix(input, injectedMarker) {
			t.Fatalf("marker survives in %q", out)
		}
	}
}
