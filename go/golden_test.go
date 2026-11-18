package redaction

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

// The golden corpus (spec/corpus) holds what the TypeScript package returned for a seeded corpus.
// Every case is JSON, so every case is replayed: the `sync` side is the standard tier in compat
// mode. Output and the count of hits per rule id must equal the record.

type goldenOpts struct {
	MaxChars *int     `json:"maxChars"`
	MaxDepth *int     `json:"maxDepth"`
	MaxNodes *int     `json:"maxNodes"`
	SkipKeys []string `json:"skipKeys"`
}

type goldenOutcome struct {
	Out  json.RawMessage `json:"out"`
	Hits [][]any         `json:"hits"`
}

type goldenCase struct {
	ID     string          `json:"id"`
	Family string          `json:"family"`
	Input  json.RawMessage `json:"input"`
	Gen    *genParts       `json:"gen"`
	Opts   goldenOpts      `json:"opts"`
	Sync   goldenOutcome   `json:"sync"`
	Async  goldenOutcome   `json:"async"`
}

type goldenFile struct {
	Count int          `json:"count"`
	Cases []goldenCase `json:"cases"`
}

func loadGolden(t *testing.T) goldenFile {
	t.Helper()
	compressed := readFile(t, "..", "spec", "corpus", "golden-b12879a.json.gz")
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if _, err := plain.ReadFrom(reader); err != nil {
		t.Fatal(err)
	}
	var golden goldenFile
	if err := json.Unmarshal(plain.Bytes(), &golden); err != nil {
		t.Fatal(err)
	}
	return golden
}

func (c goldenCase) inputJSON(t *testing.T) []byte {
	t.Helper()
	if c.Gen != nil {
		return jsonString(expandParts(t, *c.Gen))
	}
	return c.Input
}

func (c goldenCase) options() Options {
	options := Options{
		Mode:     Compat,
		MaxChars: c.Opts.MaxChars,
		MaxDepth: c.Opts.MaxDepth,
		MaxNodes: c.Opts.MaxNodes,
	}
	if c.Opts.SkipKeys != nil {
		options.SkipKeys = c.Opts.SkipKeys
	}
	return options
}

// legacyIDPrefix is the prefix of the 0.2.0 ids of the full-tier rules (`@secretlint/secretlint-rule-aws`);
// the package reports the spec ids (`aws`).
const legacyIDPrefix = "@secretlint/secretlint-rule-"

// recordedCounts is the number of hits per rule id of a recorded outcome, with the 0.2.0 prefix removed.
func recordedCounts(outcome goldenOutcome) map[string]int {
	counts := make(map[string]int)
	for _, entry := range outcome.Hits {
		counts[strings.TrimPrefix(entry[0].(string), legacyIDPrefix)]++
	}
	return counts
}

// fullOptions are the options of the async side of the corpus: the full tier in compat mode, with the
// skip keys of the case and no limits (the reference's async entry points take none).
func (c goldenCase) fullOptions() Options {
	options := Options{Tier: TierFull, Mode: Compat}
	if c.Opts.SkipKeys != nil {
		options.SkipKeys = c.Opts.SkipKeys
	}
	return options
}

// runWithResult is `run` that also returns the hit counts.
func runWithResult(t *testing.T, input []byte, opts Options) ([]byte, Result) {
	t.Helper()
	tree := parseTree(t, input)
	if tree.kind == kindString && !hasLoneSurrogate(tree.str) {
		out, result := RedactText(unitsToString(tree.str), opts)
		return jsonString(decodeUTF8(out)), result
	}
	out, result, err := RedactJSON(input, opts)
	if err != nil {
		t.Fatal(err)
	}
	return out, result
}

type digest struct {
	Digest string `json:"digest"`
	Length int    `json:"length"`
}

// matchesRecord compares the output bytes with the recorded JSON text (or, for a large output,
// its digest and length).
func matchesRecord(t *testing.T, got []byte, recorded json.RawMessage) bool {
	t.Helper()
	var summary digest
	if json.Unmarshal(recorded, &summary) == nil && summary.Digest != "" {
		sum := sha256.Sum256(got)
		length := len(utf16.Encode([]rune(string(got))))
		return hex.EncodeToString(sum[:]) == summary.Digest && length == summary.Length
	}
	return bytes.Equal(got, recorded)
}

func sameCounts(a map[string]int, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for key, count := range a {
		if b[key] != count {
			return false
		}
	}
	return true
}

func TestGoldenReplay(t *testing.T) {
	golden := loadGolden(t)
	if golden.Count != len(golden.Cases) || len(golden.Cases) != 15288 {
		t.Fatalf("the corpus holds %d cases", len(golden.Cases))
	}
	var differing []string
	for _, c := range golden.Cases {
		got, result := runWithResult(t, c.inputJSON(t), c.options())
		same := matchesRecord(t, got, c.Sync.Out) && sameCounts(countsOf(result), recordedCounts(c.Sync))
		if !same {
			differing = append(differing, c.ID)
		}
	}
	t.Logf("standard side: replayed %d cases, %d differ", len(golden.Cases), len(differing))
	if len(differing) > 0 {
		t.Fatalf("%d cases differ, first: %v", len(differing), differing[:min(len(differing), 20)])
	}
}

// awsCorrection is the one case whose full-tier result differs from the recorded 0.2.0 output: the
// AWS secret access key is reported over the secret (SPEC 4.17, decided 2026-11-18) where secretlint
// reported from the key name, and the recorded output had redacted the whole text.
var awsCorrection = struct {
	id          string
	input       string
	recordedOut string
	out         string
}{
	id:          "vector-109",
	input:       "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY9xxx1",
	recordedOut: "[REDACTED:aws]",
	out:         "AWS_SECRET_ACCESS_KEY=[REDACTED:aws]",
}

// keyCases are the cases whose full-tier result differs from the recorded 0.2.0 output because an
// object key is scanned with the full rules (decided 2026-11-18, L-N): the key holds a full-tier-only
// secret (a connection string, an npm, SendGrid, Slack webhook, Linear, Shopify or GitLab token) and is
// now replaced by the placeholder of that rule; a connection string used to read `url-credentials`.
// More redaction only: every other part of the output is the recorded one.
var keyCases = []string{
	"sample-68", "sample-119", "sample-122", "sample-125", "sample-128", "sample-131", "sample-137",
	"sample-140", "fuzz-key-39", "fuzz-key-57", "fuzz-key-82", "fuzz-key-127", "fuzz-key-167",
	"fuzz-key-189", "fuzz-key-193", "fuzz-key-198", "fuzz-key-201", "fuzz-key-211", "fuzz-key-214",
	"fuzz-key-236", "fuzz-key-266", "fuzz-key-274", "fuzz-key-280", "fuzz-key-284",
}

// sameValuesIgnoringKeys: both trees have the same shape and the same leaves, the keys may differ.
func sameValuesIgnoringKeys(a *node, b *node) bool {
	if a.kind != b.kind || len(a.items) != len(b.items) || len(a.members) != len(b.members) {
		return false
	}
	for i := range a.items {
		if !sameValuesIgnoringKeys(a.items[i], b.items[i]) {
			return false
		}
	}
	for i := range a.members {
		if !sameValuesIgnoringKeys(a.members[i].val, b.members[i].val) {
			return false
		}
	}
	return a.kind != kindString || equalUnits(a.str, b.str)
}

func TestGoldenReplayFullTier(t *testing.T) {
	golden := loadGolden(t)
	var differing []string
	for _, c := range golden.Cases {
		got, result := runWithResult(t, c.inputJSON(t), c.fullOptions())
		same := matchesRecord(t, got, c.Async.Out) && sameCounts(countsOf(result), recordedCounts(c.Async))
		if same {
			continue
		}
		differing = append(differing, c.ID)
		switch {
		case c.ID == awsCorrection.id:
			if string(c.inputJSON(t)) != string(jsonString(decodeUTF8(awsCorrection.input))) ||
				string(c.Async.Out) != string(jsonString(decodeUTF8(awsCorrection.recordedOut))) ||
				string(got) != string(jsonString(decodeUTF8(awsCorrection.out))) ||
				!sameCounts(countsOf(result), map[string]int{"aws": 1}) {
				t.Errorf("%s differs in a way the AWS correction does not explain: %s", c.ID, got)
			}
		case slices.Contains(keyCases, c.ID):
			if !sameValuesIgnoringKeys(parseTree(t, got), parseTree(t, c.Async.Out)) {
				t.Errorf("%s differs in more than its object keys: %s", c.ID, got)
			}
		}
	}
	t.Logf("full side: replayed %d cases, %d differ: %v", len(golden.Cases), len(differing), differing)
	want := append([]string{awsCorrection.id}, keyCases...)
	slices.Sort(want)
	slices.Sort(differing)
	if !slices.Equal(differing, want) {
		t.Fatalf("expected exactly the AWS correction and the key cases to differ, got %v", differing)
	}
}
