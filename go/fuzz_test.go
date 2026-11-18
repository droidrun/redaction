package redaction

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

const fuzzAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// fuzzContexts are text shapes a rule must catch, each around the marker.
var fuzzContexts = []string{
	"password=%s",
	"password: %s",
	`password="%s"`,
	"api_key=%s,next=2",
	`{"client_secret":"%s","ok":true}`,
	"session_token: %s",
	"Authorization: Bearer %s",
	"Authorization: Basic %s",
	"Authorization: Token %s",
	"https://example.test/cb?token=%s&x=1",
	"https://user:%s@example.test/x",
	"Cookie: sid=%s; theme=dark",
	"?redirect=%%3Ftoken%%3D%s",
	"postgres://svc:%s@db.test/app",
	"mongodb+srv://svc:%s@cluster.test/db?retryWrites=true",
}

// tokenShapes are key formats of the full tier around a generated body of letters and digits (or
// of letters only), each of which the full tier must redact.
var tokenShapes = []struct {
	prefix  string
	length  int
	letters bool
}{
	{"npm_", 36, false}, {"ghp_", 36, false}, {"glpat-", 20, false}, {"sk_live_", 24, false},
	{"gsk_", 52, false}, {"hf_", 34, true}, {"shpat_", 32, false}, {"lin_api_", 32, false},
	{"dckr_pat_", 27, false}, {"figd_", 40, false},
}

// tokenFor is a token of shape `index` (modulo the shapes) and its body.
func tokenFor(index uint8, seed uint32) (token string, body string) {
	shape := tokenShapes[int(index)%len(tokenShapes)]
	alphabet := fuzzAlphabet
	if shape.letters {
		alphabet = fuzzAlphabet[:52]
	}
	bytes := make([]byte, shape.length)
	for i := range bytes {
		seed = seed*1664525 + 1013904223
		bytes[i] = alphabet[int(seed>>16)%len(alphabet)]
	}
	return shape.prefix + string(bytes), string(bytes)
}

// tameText keeps only letters, digits and spaces, so random neighbours cannot change the
// context the marker sits in.
func tameText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf && strings.ContainsRune(fuzzAlphabet+" ", r) {
			return r
		}
		return ' '
	}, s)
}

func markerFor(seed uint32) string {
	body := make([]byte, 14)
	for i := range body {
		seed = seed*1664525 + 1013904223
		body[i] = fuzzAlphabet[int(seed>>16)%len(fuzzAlphabet)]
	}
	return "Zq9" + string(body) + "_x"
}

// survivingPart is the marker, its first eight or its last eight characters when the text holds
// one of them (a rule that cuts a value short leaves such a part behind), else "".
func survivingPart(text string, marker string) string {
	for _, part := range []string{marker, marker[:8], marker[len(marker)-8:]} {
		if strings.Contains(text, part) {
			return part
		}
	}
	return ""
}

func FuzzRedactText(f *testing.F) {
	f.Add("prefix words", "suffix words", uint8(0), uint32(1), "free \xff text password=abc", uint8(0))
	f.Add("", "", uint8(6), uint32(7), "[REDACTED:key-context] 日本語 😀", uint8(1))
	f.Add("a", "b", uint8(12), uint32(99), strings.Repeat("password=", 30), uint8(0))
	f.Add("x", "", uint8(3), uint32(5), strings.Repeat("ghs_1_", 50)+"."+strings.Repeat("a", 50), uint8(1))
	f.Fuzz(func(
		t *testing.T, prefix string, suffix string, context uint8, seed uint32, free string, tier uint8,
	) {
		opts := Options{Tier: Tier(tier % 2)}
		// Any input: never panics, valid UTF-8 out, same result twice.
		out, _ := RedactText(free, opts)
		again, _ := RedactText(free, opts)
		if !utf8.ValidString(out) || out != again {
			t.Fatal("output is not valid UTF-8 or not deterministic")
		}
		marker := markerFor(seed)
		shape := fuzzContexts[int(context)%len(fuzzContexts)]
		input := tameText(prefix) + " " + strings.Replace(shape, "%s", marker, 1) + " " + tameText(suffix)
		input = strings.ReplaceAll(input, "%%", "%")
		redacted, _ := RedactText(input, opts)
		if survivingPart(redacted, marker) != "" {
			t.Fatalf("part %q of the marker survives in %q", survivingPart(redacted, marker), redacted)
		}
		if opts.Tier == TierStandard {
			twice, _ := RedactText(redacted, opts)
			if twice != redacted {
				t.Fatalf("not idempotent: %q then %q", redacted, twice)
			}
		}
		// A key format of the full tier never survives it, behind anything that is not a letter.
		token, body := tokenFor(context, seed)
		full, _ := RedactText(tameText(prefix)+" "+token+" "+tameText(suffix), Options{Tier: TierFull})
		if survivingPart(full, body) != "" {
			t.Fatalf("part %q of the token survives in %q", survivingPart(full, body), full)
		}
	})
}

// fuzzDocuments are JSON documents with the marker in a place a rule must catch.
var fuzzDocuments = []string{
	`{"password":"%s"}`,
	`{"a":{"token":"%s"}}`,
	`[{"note":"password=%s"}]`,
	`{"headers":{"Authorization":"Bearer %s"}}`,
	`{"url":"https://u:%s@h.test/x"}`,
	`{"password=%s":1}`,
	`{"api_key":["%s","other"]}`,
	`{"id":"password=%s"}`,
	`{"cfg":"{\"client_secret\":\"%s\"}"}`,
	`{"db":"postgres://svc:%s@db.test/app"}`,
}

func fuzzLimit(selector uint8, value uint8) *int {
	if selector%3 != 0 {
		return nil
	}
	return Limit(int(value) % 40)
}

func FuzzRedactJSON(f *testing.F) {
	f.Add(uint8(0), uint32(1), "noise", []byte(`{"a":[1,2,{"b":null}]}`), uint8(1), uint8(5))
	f.Add(uint8(5), uint32(9), "", []byte(`[1,2,`), uint8(0), uint8(0))
	f.Add(uint8(8), uint32(3), "x y", []byte("\xff\xfe{"), uint8(3), uint8(30))
	f.Fuzz(func(
		t *testing.T, document uint8, seed uint32, noise string, free []byte, selector uint8, limit uint8,
	) {
		// Any bytes: never panics, an error comes with a non-nil text output, valid JSON comes back valid.
		tier := Tier(selector / 3 % 2)
		for _, mode := range []Mode{Strict, Compat} {
			opts := Options{
				Tier: tier, Mode: mode,
				MaxNodes: fuzzLimit(selector, limit), MaxChars: fuzzLimit(selector+1, limit),
			}
			out, _, err := RedactJSON(free, opts)
			if out == nil || (err == nil) != json.Valid(free) || (err == nil && !json.Valid(out)) {
				t.Fatalf("%q: out %q, err %v", free, out, err)
			}
		}
		marker := markerFor(seed)
		shape := fuzzDocuments[int(document)%len(fuzzDocuments)]
		encoded, _ := json.Marshal(tameText(noise))
		input := `{"k":` + strings.Replace(shape, "%s", marker, 1) + `,"n":` + string(encoded) + `}`
		opts := Options{
			Tier:     tier,
			MaxNodes: fuzzLimit(selector, limit), MaxDepth: fuzzLimit(selector+2, limit),
			MaxChars: fuzzLimit(selector+1, limit),
		}
		out, _, err := RedactJSON([]byte(input), opts)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if part := survivingPart(string(out), marker); part != "" {
			t.Fatalf("part %q survives in %s (from %s)", part, out, input)
		}
	})
}
