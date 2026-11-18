package redaction

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// redactUnbounded is RedactJSON with a parse that builds everything: the reference the limited
// parse must agree with.
func redactUnbounded(t *testing.T, data string, opts Options) string {
	t.Helper()
	e := theEngine
	lim := e.limits(opts)
	root := parseTree(t, []byte(data))
	rec := newRecorder(e)
	return string(marshal(e.walkSafely(root, opts, lim, rec)))
}

var limitDocuments = []string{
	`[1,2,3,4,5,6,7,8]`,
	`{"a":1,"b":[1,2,{"c":"xxxxxxxxxx"}],"d":"password=Zq9abcDEF123ghi_x","e":[[],{}]}`,
	`[[1,[2,[3,[4,[5]]]]],{"k":{"k":{"k":{"k":1}}}},"tail"]`,
	`{"id":"aaaaaaaaaaaaaaaaaaaa","type":"bbbbbbbbbbbbbbbbbbbb","token":"cccccccccccccccc","n":[1,2]}`,
	`[{"a":"aaaaaaaaaa"},{"b":"bbbbbbbbbb"},{"password":"cccccccccc","x":["y","z"]},"dddddddddd"]`,
	`{"a":{"b":{"c":{"d":{"e":"deep value here"}}}},"f":"password=Zq9abcDEF123ghi_x"}`,
}

// documentsWithSecretStrings hold a string under a secret-named key. Strict charges every string
// against the parse budget, while the walk replaces such a string without charging its budget, so
// with a character limit that these documents exceed the two can differ (the parse cuts earlier).
var documentsWithSecretStrings = map[int]bool{3: true, 4: true}

func TestLimitedParseEqualsUnboundedParse(t *testing.T) {
	var cases []Options
	for nodes := 0; nodes <= 14; nodes++ {
		cases = append(cases, Options{MaxNodes: Limit(nodes)})
	}
	for depth := 0; depth <= 6; depth++ {
		cases = append(cases, Options{MaxDepth: Limit(depth)})
	}
	for chars := 0; chars <= 40; chars += 4 {
		cases = append(cases, Options{MaxChars: Limit(chars)})
	}
	for _, mode := range []Mode{Strict, Compat} {
		for index, doc := range limitDocuments {
			for _, opts := range cases {
				if opts.MaxChars != nil && mode == Strict && documentsWithSecretStrings[index] {
					continue
				}
				opts.Mode = mode
				got, _, err := RedactJSON([]byte(doc), opts)
				if err != nil {
					t.Fatal(err)
				}
				if want := redactUnbounded(t, doc, opts); string(got) != want {
					t.Fatalf("mode %d, %s, nodes %v depth %v chars %v:\n got  %s\n want %s", mode, doc,
						deref(opts.MaxNodes), deref(opts.MaxDepth), deref(opts.MaxChars), got, want)
				}
			}
		}
	}
}

func deref(limit *int) string {
	if limit == nil {
		return "-"
	}
	return fmt.Sprint(*limit)
}

func TestSecretKeyStringsCountInTheParseBudget(t *testing.T) {
	doc := `{"password":"cccccccccc","list":["yy","zz"]}`
	out, _, err := RedactJSON([]byte(doc), Options{MaxChars: Limit(20)})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"password":"[REDACTED:key-context]","list":["[REDACTED:size-limit]","[REDACTED:size-limit]"]}`
	if string(out) != want {
		t.Fatalf("got %s", out)
	}
}

func TestLimitedParseStillChecksSyntaxPastTheLimits(t *testing.T) {
	inputs := []string{
		`[1,2,3,x]`, `[1,2,3,]`, `{"a":1,"b":}`, `[[[[[1]]]]` + `x`, `{"a":[1,2,{"b":tru}]}`,
		`[1,2,3,"unterminated]`, `{"a":1,"a"}`, `[1 2]`, `{"a":1 "b":2}`, `[[[[],[]],{"a":-}]]`,
	}
	for _, input := range inputs {
		for _, opts := range []Options{
			{MaxNodes: Limit(2)}, {MaxDepth: Limit(1)}, {MaxChars: Limit(1)},
			{Mode: Compat, MaxNodes: Limit(1)},
		} {
			if _, _, err := RedactJSON([]byte(input), opts); err != ErrInvalidJSON {
				t.Fatalf("%s with %+v: got %v", input, opts, err)
			}
		}
	}
}

// allocated is the number of bytes the call allocated in total.
func allocated(call func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// memoryInputs builds one input shape at a given size in bytes.
var memoryInputs = map[string]func(size int) string{
	"array of numbers": func(size int) string { return "[" + strings.Repeat("0,", size/2) + "0]" },
	"deep arrays": func(size int) string {
		return strings.Repeat("[", size/2) + strings.Repeat("]", size/2)
	},
	"flat object": func(size int) string { return "{" + strings.Repeat(`"a":"b",`, size/8) + `"z":1}` },
	"array of objects": func(size int) string {
		return "[" + strings.Repeat(`{"k":[1,2]},`, size/12) + "{}]"
	},
	"one long string": func(size int) string { return `"` + strings.Repeat("a", size) + `"` },
	"long strings in a list": func(size int) string {
		return "[" + strings.Repeat(`"`+strings.Repeat("b", 5000)+`",`, size/5000) + `"c"]`
	},
}

func allocatedFor(t *testing.T, input string, mode Mode) uint64 {
	t.Helper()
	data := []byte(input)
	return allocated(func() {
		if _, _, err := RedactJSON(data, Options{Mode: mode}); err != nil {
			t.Fatal(err)
		}
	})
}

// With the default limits a call allocates the same for a 10 MB and a 20 MB input (the work is
// bounded by the node budget), and stays far below what building every node costs (about 1.5 GB
// for 20 MB).
func TestParserMemoryFollowsTheLimitsNotTheInput(t *testing.T) {
	const small = 10_000_000
	const large = 20_000_000
	for name, build := range memoryInputs {
		ceiling := uint64(256 << 20)
		if name == "deep arrays" {
			ceiling = 32 << 20 // past the depth limit nothing is built at all
		}
		for _, mode := range []Mode{Strict, Compat} {
			isStringHeavy := name == "one long string" || name == "long strings in a list"
			if isStringHeavy && mode == Compat {
				continue // compat keeps strings as they are (SPEC 9.2): memory follows the input
			}
			atSmall := allocatedFor(t, build(small), mode)
			atLarge := allocatedFor(t, build(large), mode)
			if atLarge > ceiling || atLarge > atSmall+atSmall/4+(8<<20) {
				t.Errorf("%s (mode %d): %d MB at 10 MB, %d MB at 20 MB", name, mode, atSmall>>20, atLarge>>20)
			}
		}
	}
}
