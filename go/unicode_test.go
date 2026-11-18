package redaction

import (
	"strings"
	"testing"
)

type textCase struct {
	name     string
	input    string
	opts     Options
	expected string
}

func runTextCases(t *testing.T, cases []textCase) {
	t.Helper()
	for _, c := range cases {
		for _, mode := range []Mode{Compat, Strict} {
			opts := c.opts
			opts.Mode = mode
			t.Run(c.name, func(t *testing.T) {
				got, _ := RedactText(c.input, opts)
				if got != c.expected {
					t.Fatalf("got %q, want %q", got, c.expected)
				}
			})
		}
	}
}

const (
	secretValue = "Zq9abcDEF123ghi_x"
	keyword     = "[REDACTED:generic-keyword]"
)

func TestJavaScriptWhitespaceSet(t *testing.T) {
	runTextCases(t, []textCase{
		{"NBSP around the separator", "password\u00a0=\u00a0" + secretValue + " tail",
			Options{}, "password\u00a0=\u00a0" + keyword + " tail"},
		{"BOM around the separator", "password\ufeff=\ufeff" + secretValue + " tail",
			Options{}, "password\ufeff=\ufeff" + keyword + " tail"},
		{"U+202F around the separator", "password\u202f:\u202f" + secretValue + " tail",
			Options{}, "password\u202f:\u202f" + keyword + " tail"},
		{"U+2028 after Bearer", "Bearer\u2028abc.def-1=xyz tail",
			Options{}, "Bearer\u2028[REDACTED:auth-header] tail"},
		{"U+2028 ends a value", "password=Zq9abcDEF123\u2028ghi_x tail",
			Options{}, "password=" + keyword + "\u2028ghi_x tail"},
		{"NBSP ends a value", "password=Zq9abcDEF123\u00a0ghi_x tail",
			Options{}, "password=" + keyword + "\u00a0ghi_x tail"},
	})
}

func TestCaseFoldingIsAsciiAndKelvin(t *testing.T) {
	runTextCases(t, []textCase{
		{"Kelvin sign makes a trivial stand-in", `password="TO` + "\u212a" + `EN" other`,
			Options{}, `password="TO` + "\u212a" + `EN" other`},
		{"long s is not an s", "pa\u017f\u017fword=" + secretValue,
			Options{}, "pa\u017f\u017fword=" + secretValue},
	})
	for _, key := range []string{"p\u0130n", "PIN", "pin"} {
		out, _, err := RedactJSON([]byte(`{"`+key+`":1234}`), Options{})
		if err != nil || string(out) != `{"`+key+`":"[REDACTED:key-context]"}` {
			t.Fatalf("%q: got %s, %v", key, out, err)
		}
	}
	out, _, _ := RedactJSON([]byte(`{"P`+"\u212a"+`ey":1234}`), Options{})
	if string(out) != `{"P`+"\u212a"+`ey":1234}` {
		t.Fatalf("got %s", out)
	}
}

func TestAstralCharactersAreTwoUnits(t *testing.T) {
	key := "\U0001F511"
	runTextCases(t, []textCase{
		{"four astral characters fit eight units", strings.Repeat(key, 4), Options{MaxChars: Limit(8)},
			strings.Repeat(key, 4)},
		{"four astral characters do not fit seven", strings.Repeat(key, 4), Options{MaxChars: Limit(7)},
			"[REDACTED:size-limit]"},
		{"eight ASCII characters fit eight units", "abcdefgh", Options{MaxChars: Limit(8)}, "abcdefgh"},
		{"eight ASCII characters do not fit seven", "abcdefgh", Options{MaxChars: Limit(7)},
			"[REDACTED:size-limit]"},
		{"astral value", "password=" + strings.Repeat(key, 4), Options{}, "password=" + keyword},
		{"astral stand-in is trivial", "password=<" + strings.Repeat(key, 4) + ">", Options{},
			"password=<" + strings.Repeat(key, 4) + ">"},
		{"astral inside a quoted value", `apiKey: "Zq9abc` + "\U0001F600" + `DEF123ghi_x" tail`, Options{},
			`apiKey: "` + keyword + `" tail`},
		{"astral in URL credentials", "https://user:p\U0001F600ssw0rd@example.com/x", Options{},
			"https://user:[REDACTED:url-credentials]@example.com/x"},
		{"astral percent-encoded in a query", "?token=a%F0%9F%98%80bcdefghij&b=1", Options{},
			"?token=" + keyword + "&b=1"},
	})
}

func TestWindowCountsUnitsNotCharacters(t *testing.T) {
	key := "\U0001F511"
	window := "password=" + strings.Repeat(key, 128) + "ZZ"
	runTextCases(t, []textCase{
		{"value of 256 units is extended to the end of its run", window, Options{}, "password=" + keyword},
		{"mixed value longer than the window", "password=" + strings.Repeat("a1B", 10) +
			strings.Repeat(key, 113) + "tail", Options{}, "password=" + keyword},
	})
}

func TestInvalidUTF8IsOneUnitPerByte(t *testing.T) {
	replacement := "\ufffd"
	runTextCases(t, []textCase{
		{"invalid bytes inside a value", "password=\xff\xfe" + secretValue, Options{}, "password=" + keyword},
		{"invalid bytes before a pair", "\xff\xff\xff\xff password=" + secretValue, Options{},
			strings.Repeat(replacement, 4) + " password=" + keyword},
		{"eight invalid bytes are eight units", strings.Repeat("\xff", 8), Options{MaxChars: Limit(8)},
			strings.Repeat(replacement, 8)},
		{"eight invalid bytes do not fit seven", strings.Repeat("\xff", 8), Options{MaxChars: Limit(7)},
			"[REDACTED:size-limit]"},
		{"a truncated sequence is one unit per byte", "\xf0\x9f\x98 password=" + secretValue, Options{},
			strings.Repeat(replacement, 3) + " password=" + keyword},
	})
}

func TestLoneSurrogatesInJSONAreKept(t *testing.T) {
	cases := []jsonCase{
		{"lone high surrogate in a value", `"x=1 password=aB3\ud800aB3xyz1"`, Options{},
			`"x=1 password=[REDACTED:generic-keyword]"`},
		{"lone low surrogate after a value", `"x=1 password=aB3\udc00aB3xyz1 tail"`, Options{},
			`"x=1 password=[REDACTED:generic-keyword] tail"`},
		{"lone surrogate outside a hit", `"a\ud800b password=Zq9abcDEF123ghi_x"`, Options{},
			`"a\ud800b password=[REDACTED:generic-keyword]"`},
		{"stand-in with a lone surrogate", `{"x":"password=<\ud83d>"}`, Options{},
			`{"x":"password=<\ud83d>"}`},
	}
	runJSONCases(t, cases)
}

func TestPercentDecodeFailsWhole(t *testing.T) {
	runTextCases(t, []textCase{
		{"nested secret parameter", "?redirect=%3Ftoken%3Dabcdefgh&b=1", Options{},
			"?redirect=[REDACTED:key-context]&b=1"},
		{"overlong sequence leaves the value", "?redirect=%3Ftoken%3D%E0%80%80&b=1", Options{},
			"?redirect=%3Ftoken%3D%E0%80%80&b=1"},
		{"surrogate code point leaves the value", "?redirect=%3Ftoken%3Dabcdefgh%ED%A0%80&b=1", Options{},
			"?redirect=%3Ftoken%3Dabcdefgh%ED%A0%80&b=1"},
		{"encoded key", "?%74oken=abcdefghij&b=1", Options{}, "?%74oken=[REDACTED:key-context]&b=1"},
		{"malformed key stays whole", "?%E0%80%80token=abcdefghij&b=1", Options{},
			"?%E0%80%80token=[REDACTED:key-context]&b=1"},
	})
}

func TestEntropyUsesTheFdlibmLog2(t *testing.T) {
	table := []struct {
		count, length int
		want          float64
	}{
		{1, 3, -1.5849625007211563}, {1, 7, -2.807354922057604}, {2, 9, -2.1699250014423126},
		{3, 22, -2.8744691179161412}, {5, 13, -1.3785116232537298}, {3, 17, -2.502500340529183},
		{1, 1000003, -19.931572897402805}, {1, 22, -4.459431618637297}, {7, 44, -2.652076696579693},
		{1, 13, -3.700439718141092}, {1, 10, -3.321928094887362}, {3, 4, -0.4150374992788438},
		{11, 29, -1.398549376490275}, {17, 19, -0.1604646721932461},
	}
	for _, row := range table {
		got := log2fdlibm(float64(row.count) / float64(row.length))
		if got != row.want {
			t.Fatalf("log2(%d/%d) is %v, want %v", row.count, row.length, got, row.want)
		}
	}
}
