package redaction

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
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

// numberedKey matches a key with a collision number inside a placeholder: `[REDACTED:rule#2]`.
var numberedKey = regexp.MustCompile(`#[0-9]+\]`)

// withoutNumberedKeys is a copy of the tree without the members whose key is numbered.
func withoutNumberedKeys(n *node) *node {
	copied := &node{kind: n.kind, raw: n.raw, str: n.str, flag: n.flag}
	for _, item := range n.items {
		copied.items = append(copied.items, withoutNumberedKeys(item))
	}
	for _, entry := range n.members {
		if numberedKey.MatchString(unitsToString(entry.key)) {
			continue
		}
		copied.members = append(copied.members, member{key: entry.key, val: withoutNumberedKeys(entry.val)})
	}
	return copied
}

// collisionCases is the number of cases of the family `key-collision` whose output differs from the
// recorded 0.2.0 output on both sides, because keys that redact to the same key are now numbered and
// no value is lost (decided 2026-11-18); the recorded output kept the later value only.
const collisionCases = 120

// isNumberingOnly: the output is the recorded one plus members with numbered keys, and the hits are
// the recorded ones (the number costs no hit).
func isNumberingOnly(t *testing.T, got []byte, result Result, recorded goldenOutcome) bool {
	t.Helper()
	withoutNumbers := marshal(withoutNumberedKeys(parseTree(t, got)))
	return bytes.Equal(withoutNumbers, recorded.Out) && sameCounts(countsOf(result), recordedCounts(recorded))
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
		if same {
			continue
		}
		differing = append(differing, c.ID)
		if c.Family != "key-collision" || !isNumberingOnly(t, got, result, c.Sync) {
			t.Errorf("%s differs in more than the numbering of colliding keys: %s", c.ID, got)
		}
	}
	t.Logf("standard side: replayed %d cases, %d differ (colliding keys)", len(golden.Cases), len(differing))
	if len(differing) != collisionCases {
		t.Fatalf("expected %d key-collision cases to differ, got %d", collisionCases, len(differing))
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
// object key is scanned with the full rules (decided 2026-11-18): the key holds a full-tier-only
// secret and is now replaced by the placeholder of that rule (a connection string used to read
// `url-credentials`, the others were kept). `placeholder` is the key the output must hold, `count`
// how many times (and so how many hits of that rule). More redaction only: every other part of the
// output is the recorded one.
var keyCases = map[string]struct {
	placeholder string
	count       int
}{
	"sample-68":    {"[REDACTED:database-connection-string]", 1},
	"sample-119":   {"[REDACTED:npm]", 1},
	"sample-122":   {"[REDACTED:sendgrid]", 1},
	"sample-125":   {"[REDACTED:slack]", 1},
	"sample-128":   {"[REDACTED:linear]", 1},
	"sample-131":   {"[REDACTED:shopify]", 1},
	"sample-137":   {"[REDACTED:database-connection-string]", 1},
	"sample-140":   {"[REDACTED:gitlab]", 1},
	"fuzz-key-39":  {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-57":  {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-82":  {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-127": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-167": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-189": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-193": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-198": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-201": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-211": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-214": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-236": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-266": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-274": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-280": {"[REDACTED:database-connection-string]", 3},
	"fuzz-key-284": {"[REDACTED:database-connection-string]", 3},
}

// keyOccurrences counts the object keys of a tree that equal `key`.
func keyOccurrences(n *node, key string) int {
	count := 0
	for _, item := range n.items {
		count += keyOccurrences(item, key)
	}
	for _, entry := range n.members {
		if unitsToString(entry.key) == key {
			count++
		}
		count += keyOccurrences(entry.val, key)
	}
	return count
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

// alreadyRedactedKeys are cases whose object key is a token that the standard rules (github, aws, slack,
// stripe) already replaced in 0.2.0: the full tier finds it first, so the TypeScript package reports the
// hit under the legacy id of the rule (`@secretlint/secretlint-rule-github`), while this package reports
// the spec id (`github`, as before). Output and counts equal the recorded ones: they are not key cases.
var alreadyRedactedKeys = []string{"sample-29", "sample-41", "sample-44", "sample-47", "sample-50"}

// checkKeyCase pins what a key case changed: the placeholder key, how often it occurs, the hit
// count of its rule, and nothing but the keys.
func checkKeyCase(t *testing.T, id string, got []byte, result Result, recorded goldenOutcome) {
	t.Helper()
	want := keyCases[id]
	tree := parseTree(t, got)
	ruleID := strings.TrimSuffix(strings.TrimPrefix(want.placeholder, "[REDACTED:"), "]")
	if keyOccurrences(tree, want.placeholder) != want.count || countsOf(result)[ruleID] != want.count {
		t.Errorf("%s: %d keys %s and %d hits, want %d of each: %s", id,
			keyOccurrences(tree, want.placeholder), want.placeholder, countsOf(result)[ruleID], want.count,
			got)
	}
	if !sameValuesIgnoringKeys(tree, parseTree(t, recorded.Out)) {
		t.Errorf("%s differs in more than its object keys: %s", id, got)
	}
}

func TestGoldenReplayFullTier(t *testing.T) {
	golden := loadGolden(t)
	var differing []string
	collisions := 0
	for _, c := range golden.Cases {
		got, result := runWithResult(t, c.inputJSON(t), c.fullOptions())
		same := matchesRecord(t, got, c.Async.Out) && sameCounts(countsOf(result), recordedCounts(c.Async))
		if same {
			continue
		}
		differing = append(differing, c.ID)
		_, isKeyCase := keyCases[c.ID]
		switch {
		case c.ID == awsCorrection.id:
			if string(c.inputJSON(t)) != string(jsonString(decodeUTF8(awsCorrection.input))) ||
				string(c.Async.Out) != string(jsonString(decodeUTF8(awsCorrection.recordedOut))) ||
				string(got) != string(jsonString(decodeUTF8(awsCorrection.out))) ||
				!sameCounts(countsOf(result), map[string]int{"aws": 1}) {
				t.Errorf("%s differs in a way the AWS correction does not explain: %s", c.ID, got)
			}
		case isKeyCase:
			checkKeyCase(t, c.ID, got, result, c.Async)
		case c.Family == "key-collision" && isNumberingOnly(t, got, result, c.Async):
			collisions++
		default:
			t.Errorf("%s differs in a way no decision explains: %s", c.ID, got)
		}
	}
	t.Logf("full side: replayed %d cases, %d differ: the AWS case, %d key cases, %d colliding-key cases",
		len(golden.Cases), len(differing), len(keyCases), collisions)
	if len(differing) != 1+len(keyCases)+collisionCases || collisions != collisionCases {
		t.Fatalf("expected the AWS case, %d key cases and %d collision cases; got %d differing, %d colliding",
			len(keyCases), collisionCases, len(differing), collisions)
	}
	for _, id := range alreadyRedactedKeys {
		if slices.Contains(differing, id) {
			t.Errorf("%s changed: the standard rules already replaced the key in 0.2.0", id)
		}
	}
}
