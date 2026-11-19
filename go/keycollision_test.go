package redaction

import (
	"strings"
	"testing"
)

// Two or more different object keys that redact to the same key keep their values: the first keeps
// the plain key, each further one gets a number inside the brackets of the placeholder, in contract
// order (decided 2026-11-18). The literal cases are in spec/vectors/key-collisions.json and
// full-keys.json; the over-long keys cannot be written there.

func TestTwoOverLongKeysAreReplacedBySizeLimitAndBothAreKept(t *testing.T) {
	long := func(letter string) string { return strings.Repeat(letter, 4097) }
	runJSONCases(t, []jsonCase{{
		"two over-long keys are replaced by size-limit and both are kept",
		`{"` + long("a") + `":1,"` + long("b") + `":2}`, Options{},
		`{"[REDACTED:size-limit]":1,"[REDACTED:size-limit#2]":2}`,
	}})
}

func TestNumberedKeysAreFixedPointsAndPlaceholders(t *testing.T) {
	npm := func(letter string) string { return "npm_" + strings.Repeat(letter, 36) }
	input := `{"` + npm("A") + `":1,"` + npm("B") + `":2,"` + npm("C") + `":3}`
	for _, tier := range []Tier{TierStandard, TierFull} {
		first, _, err := RedactJSON([]byte(input), Options{Tier: tier})
		if err != nil {
			t.Fatal(err)
		}
		second, _, err := RedactJSON(first, Options{Tier: tier})
		if err != nil || string(first) != string(second) {
			t.Errorf("tier %d is not idempotent:\n %s\n %s", tier, first, second)
		}
	}
	numbered := []string{"[REDACTED:npm#2]", "[REDACTED:database-connection-string#17]", "[REDACTED:#2]"}
	for _, key := range numbered {
		if !theEngine.placeholders.isWhole(decodeUTF8(key)) {
			t.Errorf("%q is not a whole placeholder", key)
		}
	}
	// Where a number goes (SPEC 8, rule 3 and 4): the last placeholder must be exactly `[REDACTED:<rule>]`,
	// a rule with no `:suffix` that does not itself end with the number mark and digits.
	places := map[string]int{ // key -> the unit before which `#n` goes, or -1
		"[REDACTED:npm]":                      13,
		"token [REDACTED:npm] end":            19,
		"x [REDACTED:npm] y [REDACTED:npm]":   32,
		"[REDACTED:x#]":                       12,
		"[REDACTED:a#b2]":                     14,
		"no placeholder here":                 -1,
		"a [REDACTED] b":                      -1,
		"[REDACTED]":                          -1,
		"[REDACTED:a:b]":                      -1,
		"[REDACTED:npm#2]":                    -1,
		"[REDACTED:#5]":                       -1,
		"[REDACTED:npm] [REDACTED:npm#2]":     -1,
		"[REDACTED:npm#2] [REDACTED:npm]":     30,
		"[REDACTED:npm] [REDACTED]":           -1,
		"[REDACTED:npm] [REDACTED:a:b]":       -1,
		"password=[REDACTED:generic-keyword]": 34,
	}
	for key, want := range places {
		at, ok := theEngine.placeholders.numberAt(decodeUTF8(key))
		if ok != (want >= 0) || (ok && at != want) {
			t.Errorf("%q: got %d, %v; want %d", key, at, ok, want)
		}
	}
	at, _ := theEngine.placeholders.numberAt(decodeUTF8("x [REDACTED:npm] y [REDACTED:npm]"))
	renumbered := theEngine.placeholders.numbered(decodeUTF8("x [REDACTED:npm] y [REDACTED:npm]"), at, 3)
	if unitsToString(renumbered) != "x [REDACTED:npm] y [REDACTED:npm#3]" {
		t.Errorf("the last placeholder: got %q", unitsToString(renumbered))
	}
}

func TestCollisionNumbersCostNoHitsAndTheVerdictIsThePlainOne(t *testing.T) {
	npm := func(letter string) string { return "npm_" + strings.Repeat(letter, 36) }
	_, result, err := RedactJSON([]byte(`{"`+npm("A")+`":1,"`+npm("B")+`":2}`), Options{Tier: TierFull})
	if err != nil || len(result.Hits) != 1 || result.Hits[0] != (RuleCount{"npm", 2}) {
		t.Fatalf("got %+v, %v", result, err)
	}
	// A numbered placeholder key names no secret: the verdict is the one of the plain placeholder.
	numbered, plain := KeyVerdict("[REDACTED:npm#2]"), KeyVerdict("[REDACTED:npm]")
	if numbered != plain || numbered != VerdictNone {
		t.Errorf("verdicts %v and %v", numbered, plain)
	}
}
