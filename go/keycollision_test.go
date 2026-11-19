package redaction

import (
	"strings"
	"testing"
)

// Two or more different object keys that redact to the same key keep their values: the first keeps
// the plain key, each further one gets a number inside the brackets of the placeholder, in contract
// order (decided 2026-11-18).

func collisionCase(name string, tier Tier, input string, want string) jsonCase {
	return jsonCase{name: name, input: input, opts: Options{Tier: tier}, expected: want}
}

func TestCollidingKeysAreNumbered(t *testing.T) {
	npm := func(letter string) string { return "npm_" + strings.Repeat(letter, 36) }
	long := func(letter string) string { return strings.Repeat(letter, 4097) }
	for _, mode := range []Mode{Compat, Strict} {
		cases := []jsonCase{
			collisionCase("two connection strings", TierFull,
				`{"postgres://a:pass1234@h/x":"v1","mysql://b:pass5678@h/y":"v2"}`,
				`{"[REDACTED:database-connection-string]":"v1",`+
					`"[REDACTED:database-connection-string#2]":"v2"}`),
			collisionCase("three tokens", TierFull,
				`{"`+npm("A")+`":1,"`+npm("B")+`":2,"`+npm("C")+`":3}`,
				`{"[REDACTED:npm]":1,"[REDACTED:npm#2]":2,"[REDACTED:npm#3]":3}`),
			collisionCase("a numbered key that is already taken", TierFull,
				`{"`+npm("A")+`":1,"[REDACTED:npm#2]":9,"`+npm("B")+`":2}`,
				`{"[REDACTED:npm]":1,"[REDACTED:npm#2]":9,"[REDACTED:npm#3]":2}`),
			collisionCase("a key that only holds placeholders: the number goes into the last one", TierFull,
				`{"x `+npm("A")+` y `+npm("B")+` z":1,"x `+npm("C")+` y `+npm("D")+` z":2}`,
				`{"x [REDACTED:npm] y [REDACTED:npm] z":1,"x [REDACTED:npm] y [REDACTED:npm#2] z":2}`),
			collisionCase("partly replaced keys of the standard tier are numbered", TierStandard,
				`{"password=Zq9AAAAAAAAAAAAAA_x":1,"password=Zq9BBBBBBBBBBBBBB_x":"s","note":"n"}`,
				`{"password=[REDACTED:generic-keyword]":"[REDACTED:key-context]",`+
					`"password=[REDACTED:generic-keyword#2]":"[REDACTED:key-context]","note":"n"}`),
			collisionCase("whole keys of the standard tier are numbered", TierStandard,
				`{"first":1,"ghp_`+strings.Repeat("a", 36)+`":"a","ghp_`+strings.Repeat("b", 36)+
					`":"b","ghp_`+strings.Repeat("c", 36)+`":"c"}`,
				`{"first":1,"[REDACTED:github]":"a","[REDACTED:github#2]":"b","[REDACTED:github#3]":"c"}`),
			collisionCase("a key that already is the placeholder takes the plain key", TierFull,
				`{"[REDACTED:npm]":1,"`+npm("A")+`":2}`, `{"[REDACTED:npm]":1,"[REDACTED:npm#2]":2}`),
			collisionCase("an unchanged key keeps its name wherever it stands in the object", TierFull,
				`{"`+npm("A")+`":1,"[REDACTED:npm]":2}`, `{"[REDACTED:npm#2]":1,"[REDACTED:npm]":2}`),
			collisionCase("a numbered name that an unchanged key reserves later is skipped", TierFull,
				`{"`+npm("A")+`":1,"`+npm("B")+`":2,"[REDACTED:npm#2]":9}`,
				`{"[REDACTED:npm]":1,"[REDACTED:npm#3]":2,"[REDACTED:npm#2]":9}`),
			collisionCase("an unchanged key is never numbered", TierFull,
				`{"[REDACTED:npm#2]":9,"`+npm("A")+`":1,"`+npm("B")+`":2}`,
				`{"[REDACTED:npm#2]":9,"[REDACTED:npm]":1,"[REDACTED:npm#3]":2}`),
			collisionCase("keys that do not collide are untouched", TierFull,
				`{"`+npm("A")+`":1,"mid":2,"other":3}`, `{"[REDACTED:npm]":1,"mid":2,"other":3}`),
			collisionCase("collisions in nested objects count apart", TierFull,
				`{"`+npm("A")+`":{"`+npm("B")+`":1,"`+npm("C")+`":2},"`+npm("D")+`":3}`,
				`{"[REDACTED:npm]":{"[REDACTED:npm]":1,"[REDACTED:npm#2]":2},"[REDACTED:npm#2]":3}`),
		}
		for i := range cases {
			cases[i].name += " (mode " + map[Mode]string{Compat: "compat", Strict: "strict"}[mode] + ")"
			cases[i].opts.Mode = mode
		}
		runJSONCases(t, cases)
	}
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
