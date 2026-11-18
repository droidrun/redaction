package redaction

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// parseTree reads JSON the way the package does (order kept, duplicate keys applied).
func parseTree(t *testing.T, raw []byte) *node {
	t.Helper()
	tree, err := parseJSON(raw)
	if err != nil {
		t.Fatalf("test data is not JSON: %v", err)
	}
	return tree
}

func sameValue(t *testing.T, got []byte, want []byte) bool {
	t.Helper()
	return reflect.DeepEqual(parseTree(t, got), parseTree(t, want))
}

type genParts struct {
	Parts [][]json.RawMessage `json:"parts"`
}

// expandParts builds a long string from `[unit, times]` parts (SPEC 14).
func expandParts(t *testing.T, parts genParts) []uint16 {
	t.Helper()
	var units []uint16
	for _, part := range parts.Parts {
		var unit string
		var times int
		if json.Unmarshal(part[0], &unit) != nil || json.Unmarshal(part[1], &times) != nil {
			t.Fatal("bad generated input")
		}
		piece := asUnits(unit)
		if node := parseTree(t, part[0]); node.kind == kindString {
			piece = node.str
		}
		for i := 0; i < times; i++ {
			units = append(units, piece...)
		}
	}
	return units
}

func hasLoneSurrogate(units []uint16) bool {
	for i := 0; i < len(units); i++ {
		switch {
		case isHighSurrogate(units[i]) && i+1 < len(units) && isLowSurrogate(units[i+1]):
			i++
		case isSurrogate(units[i]):
			return true
		}
	}
	return false
}

func readFile(t *testing.T, path ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(path...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func jsonString(units []uint16) []byte {
	return appendString(nil, units)
}

func countsOf(result Result) map[string]int {
	counts := make(map[string]int)
	for _, entry := range result.Hits {
		counts[entry.RuleID] += entry.Count
	}
	return counts
}
