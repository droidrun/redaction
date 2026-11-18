package redaction

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func embeddedFiles(t *testing.T) specFileSet {
	t.Helper()
	files, err := readEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestEmbeddedSpecMatchesTheGeneratedHash(t *testing.T) {
	if err := verifySpec(embeddedFiles(t), specHash); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedSpecEqualsTheSpecDirectory(t *testing.T) {
	files := embeddedFiles(t)
	pairs := map[string][]byte{
		"rules.json":      files.rules,
		"keys.json":       files.keys,
		"algorithms.json": files.algorithms,
	}
	for name, embedded := range pairs {
		if string(readFile(t, "..", "spec", name)) != string(embedded) {
			t.Fatalf("%s: the embedded copy differs from spec/", name)
		}
	}
}

func TestChangedValueFailsTheIntegrityCheck(t *testing.T) {
	files := embeddedFiles(t)
	changed := files
	changed.rules = []byte(strings.Replace(string(files.rules), "AIza", "AIzb", 1))
	if err := verifySpec(changed, specHash); err != errSpecIntegrity {
		t.Fatalf("got %v", err)
	}
	other := files
	algorithms := string(files.algorithms)
	other.algorithms = []byte(strings.Replace(algorithms, `"minScanLength": 8`, `"minScanLength": 9`, 1))
	if err := verifySpec(other, specHash); err != errSpecIntegrity {
		t.Fatalf("got %v", err)
	}
}

func TestUnsupportedVersionAndEmptyRulesAreRefused(t *testing.T) {
	files := embeddedFiles(t)
	versioned := files
	versioned.keys = []byte(strings.Replace(string(files.keys), `"specVersion": 1`, `"specVersion": 2`, 1))
	if _, err := decodeSpec(versioned); err != errSpecRejected {
		t.Fatalf("version: got %v", err)
	}
	var rules map[string]any
	if err := json.Unmarshal(files.rules, &rules); err != nil {
		t.Fatal(err)
	}
	rules["pipeline"] = []any{}
	emptied := files
	emptied.rules, _ = json.Marshal(rules)
	if _, err := decodeSpec(emptied); err != errSpecRejected {
		t.Fatalf("empty pipeline: got %v", err)
	}
	var keys map[string]any
	if err := json.Unmarshal(files.keys, &keys); err != nil {
		t.Fatal(err)
	}
	keys["secretWords"] = []any{}
	noWords := files
	noWords.keys, _ = json.Marshal(keys)
	if _, err := decodeSpec(noWords); err != errSpecRejected {
		t.Fatalf("no secret words: got %v", err)
	}
}

func TestSpecFailuresNameTheFailureNotTheData(t *testing.T) {
	for _, err := range []error{errSpecRejected, errSpecIntegrity, ErrInvalidJSON, errTextTooLarge} {
		if !strings.HasPrefix(err.Error(), "redaction: ") || len(err.Error()) > 80 {
			t.Fatalf("unexpected message %q", err)
		}
	}
}

func TestEngineIsBuiltFromTheEmbeddedSpec(t *testing.T) {
	if theEngine == nil || len(theEngine.pipeline) != 18 {
		t.Fatal("the engine does not hold the pipeline of the spec")
	}
}

// classPatterns collects every class of the pipeline: the guard classes and every field whose
// name ends in Class, Char, Stop or End (SPEC 2).
func classPatterns(t *testing.T) []string {
	t.Helper()
	var rules struct {
		Pipeline []map[string]json.RawMessage `json:"pipeline"`
	}
	if err := json.Unmarshal(embeddedFiles(t).rules, &rules); err != nil {
		t.Fatal(err)
	}
	var classes []string
	for _, rule := range rules.Pipeline {
		for name, raw := range rule {
			var value string
			if json.Unmarshal(raw, &value) != nil || !isClassField(name) {
				continue
			}
			classes = append(classes, value)
		}
	}
	return classes
}

func isClassField(name string) bool {
	for _, suffix := range []string{"Class", "Char", "Stop", "End", "notBefore", "notAfter"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func TestClassTablesEqualTheRegexpEngine(t *testing.T) {
	spec := theEngine.spec
	templates := append(classPatterns(t), "[{{WS}}]", spec.algorithms.Trivial.WrapperInner)
	templates = append(templates, spec.algorithms.Evidence.Classes...)
	if len(templates) < 20 {
		t.Fatalf("only %d classes found", len(templates))
	}
	for _, template := range templates {
		expanded, err := spec.expand(template)
		if err != nil {
			t.Fatal(err)
		}
		set, err := parseClass(expanded)
		if err != nil {
			t.Fatalf("%s: %v", template, err)
		}
		searcher, err := newSearcher("^" + expanded + "$")
		if err != nil {
			t.Fatal(err)
		}
		for unit := 0; unit <= 0xFFFF; unit++ {
			probe := newText([]uint16{uint16(unit)})
			isMember := searcher.plain.MatchString(probe.mapped)
			if isMember != set.has(uint16(unit)) {
				t.Fatalf("%s: unit %04x is %v in the table", template, unit, set.has(uint16(unit)))
			}
		}
	}
}

func TestMappedTextHasOneCharacterPerUnit(t *testing.T) {
	units := []uint16{'a', 0xD83D, 0xDD11, 0xD800, 0x00E9, 0xFFFD}
	mapped := newText(units)
	if utf8.RuneCountInString(mapped.mapped) != len(units) {
		t.Fatal("the mapped text has more or fewer characters than units")
	}
	for i := range units {
		if mapped.unitAt(mapped.byteAt(i)) != i {
			t.Fatalf("unit %d does not map back", i)
		}
	}
}
