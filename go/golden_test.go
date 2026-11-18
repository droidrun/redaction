package redaction

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// hasZeroLimit is true for a case that sets a limit to 0. In Go a zero limit means the default,
// so such a case cannot be asked; the replay leaves it out and counts it.
func (o goldenOpts) hasZeroLimit() bool {
	for _, limit := range []*int{o.MaxChars, o.MaxDepth, o.MaxNodes} {
		if limit != nil && *limit == 0 {
			return true
		}
	}
	return false
}

func valueOr(limit *int) int {
	if limit == nil {
		return 0
	}
	return *limit
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
		MaxChars: valueOr(c.Opts.MaxChars),
		MaxDepth: valueOr(c.Opts.MaxDepth),
		MaxNodes: valueOr(c.Opts.MaxNodes),
	}
	if c.Opts.SkipKeys != nil {
		options.SkipKeys = c.Opts.SkipKeys
	}
	return options
}

func (c goldenCase) recordedCounts() map[string]int {
	counts := make(map[string]int)
	for _, entry := range c.Sync.Hits {
		counts[entry[0].(string)]++
	}
	return counts
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

// matchesRecord compares the output with the recorded one (a value, or the digest and length of
// its JSON text for a large output).
func matchesRecord(t *testing.T, got []byte, recorded json.RawMessage) bool {
	t.Helper()
	var summary digest
	if json.Unmarshal(recorded, &summary) == nil && summary.Digest != "" {
		sum := sha256.Sum256(got)
		length := len(utf16.Encode([]rune(string(got))))
		return hex.EncodeToString(sum[:]) == summary.Digest && length == summary.Length
	}
	return sameValue(t, got, recorded)
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
	if golden.Count != len(golden.Cases) || golden.Count < 5000 {
		t.Fatalf("the corpus holds %d cases", len(golden.Cases))
	}
	var differing []string
	replayed := 0
	for _, c := range golden.Cases {
		if c.Opts.hasZeroLimit() {
			continue
		}
		replayed++
		got, result := runWithResult(t, c.inputJSON(t), c.options())
		same := matchesRecord(t, got, c.Sync.Out) && sameCounts(countsOf(result), c.recordedCounts())
		if !same {
			differing = append(differing, c.ID)
		}
	}
	t.Logf("replayed %d of %d cases, %d differ", replayed, len(golden.Cases), len(differing))
	if replayed < 15000 {
		t.Fatalf("only %d cases replayed", replayed)
	}
	if len(differing) > 0 {
		t.Fatalf("%d cases differ, first: %v", len(differing), differing[:min(len(differing), 20)])
	}
}
