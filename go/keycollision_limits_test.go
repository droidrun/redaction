package redaction

import (
	"strings"
	"testing"
)

// Key collisions under limits (SPEC 8, rules 1 and 3): every input key of an object that holds a placeholder
// is reserved, also one that a node limit leaves out, and a key that the character budget replaces is a
// changed key even when it reads the same. Expected values are the output of the reference.

func limitCase(name string, input string, opts Options, want string) jsonCase {
	return jsonCase{name: name, input: input, opts: opts, expected: want}
}

func TestReservedKeysUnderALimit(t *testing.T) {
	a := "ghp_" + strings.Repeat("a", 36)
	nodes2 := Options{Mode: Compat, MaxNodes: Limit(2)}
	strictNodes2 := Options{Mode: Strict, MaxNodes: Limit(2)}
	strictChars10 := Options{Mode: Strict, MaxChars: Limit(10)}
	runJSONCases(t, []jsonCase{
		limitCase("the first entry left out is reserved",
			`{"`+a+`":"keep-me","[REDACTED:github]":2}`, nodes2,
			`{"[REDACTED:github#2]":"keep-me","[REDACTED:github]":"[REDACTED:size-limit]"}`),
		limitCase("a later entry left out is reserved too",
			`{"`+a+`":"keep","x":1,"[REDACTED:github]":2}`, nodes2,
			`{"[REDACTED:github#2]":"keep","x":"[REDACTED:size-limit]"}`),
		limitCase("strict: an entry left out is reserved", `{"`+a+`":"keep","x":1,"[REDACTED:github]":2}`,
			strictNodes2, `{"[REDACTED:github#2]":"keep","[REDACTED:size-limit]":"[REDACTED:size-limit]"}`),
		limitCase("strict: a key that reads like the budget placeholder is changed",
			`{"[REDACTED:size-limit]":1,"`+a+`":2}`, strictChars10,
			`{"[REDACTED:size-limit]":1,"[REDACTED:size-limit#2]":2}`),
		limitCase("strict: the same, the other way round",
			`{"`+a+`":2,"[REDACTED:size-limit]":1}`, strictChars10,
			`{"[REDACTED:size-limit]":2,"[REDACTED:size-limit#2]":1}`),
		limitCase("strict: the collapsed rest takes a free number", `{"[REDACTED:size-limit]":1,"b":2,"c":3}`,
			Options{Mode: Strict, MaxNodes: Limit(3)},
			`{"[REDACTED:size-limit]":1,"b":2,"[REDACTED:size-limit#2]":"[REDACTED:size-limit]"}`),
	})
}

// Under the strict character limit the full-tier key scan replaces a key longer than the limit, so a
// placeholder-holding input key longer than the limit is not reserved there (SPEC 8 rule 1: only keys within
// the budget can be left as they are), in either tier. Expected values are the
// output of the reference for both entry points.
func TestStrictCharacterLimitAndReservedKeys(t *testing.T) {
	a := "ghp_" + strings.Repeat("a", 36)
	b := "ghp_" + strings.Repeat("b", 36)
	n := "npm_" + strings.Repeat("A", 36)
	strictChars8 := func(tier Tier) Options { return Options{Tier: tier, Mode: Strict, MaxChars: Limit(8)} }
	for _, tier := range []Tier{TierStandard, TierFull} {
		runJSONCases(t, []jsonCase{
			limitCase("a key that reads like the size-limit placeholder is beyond the budget and not reserved",
				`{"`+n+`":1,"[REDACTED:size-limit]":2}`, strictChars8(tier),
				`{"[REDACTED:size-limit]":1,"[REDACTED:size-limit#2]":2}`),
			limitCase("a placeholder key over the limit is replaced like any key over it",
				`{"`+n+`":1,"[REDACTED:npm#2]":2}`, strictChars8(tier),
				`{"[REDACTED:size-limit]":1,"[REDACTED:size-limit#2]":2}`),
		})
	}
	input := `{"` + a + `":1,"` + b + `":2,"[REDACTED:size-limit#2]":3}`
	runJSONCases(t, []jsonCase{
		limitCase("standard: the numbered key over the limit is not reserved", input, strictChars8(TierStandard),
			`{"[REDACTED:size-limit]":1,"[REDACTED:size-limit#2]":2,"[REDACTED:size-limit#3]":3}`),
		limitCase("full: the numbered key over the limit is not reserved", input, strictChars8(TierFull),
			`{"[REDACTED:size-limit]":1,"[REDACTED:size-limit#2]":2,"[REDACTED:size-limit#3]":3}`),
	})
}

// Keys that a node limit leaves out are kept for reservation up to the character limit; past it the walk
// still never writes a duplicate key (the entry written as it was replaces an earlier one, as in the
// reference).
func TestNoDuplicateKeyWhenTheReservationRoomIsUsedUp(t *testing.T) {
	a := "ghp_" + strings.Repeat("a", 36)
	input := `{"` + a + `":1,"x1":2,"[REDACTED:github]":3}`
	out, _, err := RedactJSON([]byte(input), Options{Mode: Compat, MaxNodes: Limit(2), MaxChars: Limit(0)})
	if err != nil {
		t.Fatal(err)
	}
	tree := parseTree(t, out)
	seen := map[string]bool{}
	for _, entry := range tree.members {
		name := unitsToString(entry.key)
		if seen[name] {
			t.Fatalf("duplicate key %q in %s", name, out)
		}
		seen[name] = true
	}
}

func TestEdgeLastPlaceholdersKeepTheOldRule(t *testing.T) {
	a := "ghp_" + strings.Repeat("a", 36)
	b := "ghp_" + strings.Repeat("b", 36)
	for _, mode := range []Mode{Compat, Strict} {
		runJSONCases(t, []jsonCase{
			limitCase("a bare last placeholder is not numbered: the later value wins",
				`{"`+a+` [REDACTED]":1,"`+b+` [REDACTED]":2}`, Options{Mode: mode},
				`{"[REDACTED:github] [REDACTED]":2}`),
			limitCase("a last placeholder with a suffix is not numbered",
				`{"`+a+` [REDACTED:a:b]":1,"`+b+` [REDACTED:a:b]":2}`, Options{Mode: mode},
				`{"[REDACTED:github] [REDACTED:a:b]":2}`),
			limitCase("an already numbered last placeholder is not numbered again",
				`{"`+a+` [REDACTED:x#2]":1,"`+b+` [REDACTED:x#2]":2}`, Options{Mode: mode},
				`{"[REDACTED:github] [REDACTED:x#2]":2}`),
			limitCase("a rule that only ends with the mark is numbered",
				`{"`+a+` [REDACTED:x#]":1,"`+b+` [REDACTED:x#]":2}`, Options{Mode: mode},
				`{"[REDACTED:github] [REDACTED:x#]":1,"[REDACTED:github] [REDACTED:x##2]":2}`),
		})
	}
}
