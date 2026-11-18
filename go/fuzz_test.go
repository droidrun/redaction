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
	f.Add("prefix words", "suffix words", uint8(0), uint32(1), "free \xff text password=abc")
	f.Add("", "", uint8(6), uint32(7), "[REDACTED:key-context] 日本語 😀")
	f.Add("a", "b", uint8(12), uint32(99), strings.Repeat("password=", 30))
	f.Fuzz(func(t *testing.T, prefix string, suffix string, context uint8, seed uint32, free string) {
		// Any input: never panics, valid UTF-8 out, same result twice.
		out, _ := RedactText(free, Options{})
		again, _ := RedactText(free, Options{})
		if !utf8.ValidString(out) || out != again {
			t.Fatal("output is not valid UTF-8 or not deterministic")
		}
		marker := markerFor(seed)
		shape := fuzzContexts[int(context)%len(fuzzContexts)]
		input := tameText(prefix) + " " + strings.Replace(shape, "%s", marker, 1) + " " + tameText(suffix)
		input = strings.ReplaceAll(input, "%%", "%")
		redacted, _ := RedactText(input, Options{})
		if survivingPart(redacted, marker) != "" {
			t.Fatalf("part %q of the marker survives in %q", survivingPart(redacted, marker), redacted)
		}
		twice, _ := RedactText(redacted, Options{})
		if twice != redacted {
			t.Fatalf("not idempotent: %q then %q", redacted, twice)
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
	f.Fuzz(func(t *testing.T, document uint8, seed uint32, noise string, free []byte, selector uint8, limit uint8) {
		// Any bytes: never panics, an error comes with a non-nil text output, valid JSON comes back valid.
		for _, mode := range []Mode{Strict, Compat} {
			opts := Options{Mode: mode, MaxNodes: fuzzLimit(selector, limit), MaxChars: fuzzLimit(selector+1, limit)}
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
			MaxNodes: fuzzLimit(selector, limit), MaxDepth: fuzzLimit(selector+2, limit), MaxChars: fuzzLimit(selector+1, limit),
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
