package redaction

import (
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
		if strings.Contains(redacted, marker) {
			t.Fatalf("marker survives in %q", redacted)
		}
		twice, _ := RedactText(redacted, Options{})
		if twice != redacted {
			t.Fatalf("not idempotent: %q then %q", redacted, twice)
		}
	})
}
