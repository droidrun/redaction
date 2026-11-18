//go:build !race

package redaction

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The attacks come from tools/lib/attacks.ts (go/testdata/gen-attacks.ts writes them). A plain attack
// is a unit repeated to a size; a composite one starts with a short cluster (`head`) and then repeats
// its unit: a long run behind many starts. Each is run at 100 KB and at 1 MB two ways: through the
// interpreter (the standard rules and the full-tier rules over the whole text, no windows: every rule
// kind with its restart loops, as `tools/lint/scaling-interpreter.ts` does), and through the public
// call with the full tier (windows, merge, splice). The time at 1 MB must stay near-linear against
// 100 KB, and a composite attack may cost at most a fixed multiple of the plain text of its size
// (SPEC 4.11, 10).
const (
	smallSize       = 100_000
	largeSize       = 1_000_000
	ratioLimit      = 30
	ratioFloor      = 10 * time.Millisecond
	absoluteLimit   = 10 * time.Second
	compositeFactor = 20
	compositeFloor  = 20 * time.Millisecond
)

type attack struct {
	Name string `json:"name"`
	Unit string `json:"unit"`
	Head string `json:"head"`
}

// textAt is the attack at `size` units: the head, then the unit repeated up to the size.
func (a attack) textAt(size int) string {
	head, unit := decodeUTF8(a.Head), decodeUTF8(a.Unit)
	units := make([]uint16, 0, size)
	units = append(units, head...)
	for len(units) < size {
		units = append(units, unit...)
	}
	return unitsToString(units[:max(size, 0)])
}

// runners are the two ways an attack text is run.
var runners = map[string]func(text string){
	"interpreter": func(text string) {
		t := textFromString(text)
		theEngine.detect(t)
		theEngine.detectFullRules(t)
	},
	"RedactText": func(text string) { RedactText(text, Options{Tier: TierFull}) },
}

// timeRun times one call under a deadline. A call that never returns cannot be killed inside the
// process, so the test fails when the deadline passes and the run ends with it.
func timeRun(t *testing.T, name string, input string, run func(string)) time.Duration {
	t.Helper()
	elapsed := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		run(input)
		elapsed <- time.Since(started)
	}()
	select {
	case taken := <-elapsed:
		return taken
	case <-time.After(absoluteLimit):
		t.Fatalf("attack %s: no result after %v on %d bytes", name, absoluteLimit, len(input))
		return 0
	}
}

func loadAttacks(t *testing.T) []attack {
	t.Helper()
	var attacks []attack
	if err := json.Unmarshal(readFile(t, "testdata", "attacks.json"), &attacks); err != nil {
		t.Fatal(err)
	}
	if len(attacks) < 300 {
		t.Fatalf("only %d attacks", len(attacks))
	}
	return attacks
}

func TestAttackStringsScaleLinearly(t *testing.T) {
	attacks := loadAttacks(t)
	for _, way := range []string{"interpreter", "RedactText"} {
		run := runners[way]
		plain := timeRun(t, "plain", attack{Unit: "a"}.textAt(largeSize), run)
		var slowest time.Duration
		composites := 0
		for _, a := range attacks {
			small := timeRun(t, a.Name, a.textAt(smallSize), run)
			large := timeRun(t, a.Name, a.textAt(largeSize), run)
			slowest = max(slowest, large)
			if large > absoluteLimit || large > ratioLimit*max(small, ratioFloor) {
				t.Errorf("%s, attack %s: %v at 100 KB, %v at 1 MB", way, a.Name, small, large)
			}
			if a.Head == "" {
				continue
			}
			composites++
			if large > compositeFactor*max(plain, compositeFloor) {
				t.Errorf("%s, attack %s: %v at 1 MB, more than %d times the plain text (%v)", way, a.Name,
					large, compositeFactor, plain)
			}
		}
		if composites < 2 {
			t.Fatalf("only %d composite attacks", composites)
		}
		t.Logf("%s: %d attacks, %d composite; slowest run at 1 MB: %v; plain text: %v", way, len(attacks),
			composites, slowest, plain)
	}
}

// shortest is the best of a few runs: the noise of a busy machine only makes a run slower.
func shortest(t *testing.T, name string, input string, run func(string)) time.Duration {
	t.Helper()
	best := timeRun(t, name, input, run)
	for i := 0; i < 2; i++ {
		best = min(best, timeRun(t, name, input, run))
	}
	return best
}

// The run memory is per part (SPEC 4.11): `ghs_1_` repeated, then `.`, then a long run measures the long
// run once, however many starts the cluster has. A memory per class is overwritten by the other parts of
// the same class and measures it again at every start (170 times as much work with 170 starts), so the
// text with 170 starts must cost about as much as the one with 2.
func TestAttackStringsRunMemoIsPerPart(t *testing.T) {
	const run = 1_000_000
	build := func(starts int) string {
		return strings.Repeat("ghs_1_", starts) + "." + strings.Repeat("a", run)
	}
	scan := runners["interpreter"]
	many := shortest(t, "170 starts", build(170), scan)
	few := shortest(t, "2 starts", build(2), scan)
	t.Logf("170 starts: %v, 2 starts: %v", many, few)
	if many > 3*max(few, compositeFloor) {
		t.Fatalf("170 starts cost %v, 2 starts %v: the long run is measured again at every start", many, few)
	}
}
