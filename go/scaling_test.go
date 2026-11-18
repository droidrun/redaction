//go:build !race

package redaction

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The attack units come from tools/lib/attacks.ts (go/testdata/gen-attacks.ts writes them): each
// unit is repeated to 100 KB and to 1 MB and run through the interpreter. The time at 1 MB must
// stay near-linear against 100 KB (SPEC 10).
const (
	smallSize     = 100_000
	largeSize     = 1_000_000
	ratioLimit    = 30
	ratioFloor    = 10 * time.Millisecond
	absoluteLimit = 10 * time.Second
)

func repeatedTo(unit string, size int) string {
	return strings.Repeat(unit, size/len(unit)+1)[:size]
}

// timeRun times one call under a deadline. A call that never returns cannot be killed inside the
// process, so the test fails when the deadline passes and the run ends with it.
func timeRun(t *testing.T, attack string, input string) time.Duration {
	t.Helper()
	elapsed := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		RedactText(input, Options{})
		elapsed <- time.Since(started)
	}()
	select {
	case taken := <-elapsed:
		return taken
	case <-time.After(absoluteLimit):
		t.Fatalf("attack %q: no result after %v on %d units", attack, absoluteLimit, len(input))
		return 0
	}
}

func TestAttackStringsScaleLinearly(t *testing.T) {
	var units []string
	if err := json.Unmarshal(readFile(t, "testdata", "attacks.json"), &units); err != nil {
		t.Fatal(err)
	}
	if len(units) < 100 {
		t.Fatalf("only %d attack units", len(units))
	}
	var slowest time.Duration
	for _, unit := range units {
		small := timeRun(t, unit, repeatedTo(unit, smallSize))
		large := timeRun(t, unit, repeatedTo(unit, largeSize))
		slowest = max(slowest, large)
		if large > absoluteLimit || large > ratioLimit*max(small, ratioFloor) {
			t.Errorf("attack %q: %v at 100 KB, %v at 1 MB", unit, small, large)
		}
	}
	t.Logf("slowest run at 1 MB: %v", slowest)
}
