package redaction

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type vectorCase struct {
	Name             string          `json:"name"`
	Input            json.RawMessage `json:"input"`
	InputGen         *genParts       `json:"inputGen"`
	Mode             string          `json:"mode"`
	Opts             vectorOpts      `json:"opts"`
	Expected         json.RawMessage `json:"expected"`
	ExpectedSync     json.RawMessage `json:"expectedSync"`
	ExpectedGenSync  *genParts       `json:"expectedGenSync"`
	ExpectedGenAsync *genParts       `json:"expectedGenAsync"`
}

type vectorOpts struct {
	MaxChars *int `json:"maxChars"`
	MaxDepth *int `json:"maxDepth"`
	MaxNodes *int `json:"maxNodes"`
}

type vectorFile struct {
	Description string       `json:"description"`
	Cases       []vectorCase `json:"cases"`
}

func loadVectors(t *testing.T) map[string]vectorFile {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("spec", "vectors", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatal("no vector files")
	}
	sort.Strings(files)
	loaded := make(map[string]vectorFile)
	for _, path := range files {
		var file vectorFile
		if err := json.Unmarshal(readFile(t, path), &file); err != nil {
			t.Fatal(err)
		}
		loaded[strings.TrimSuffix(filepath.Base(path), ".json")] = file
	}
	return loaded
}

func (c vectorCase) options() Options {
	mode := Compat
	if c.Mode == "strict" {
		mode = Strict
	}
	limits := c.Opts
	return Options{Mode: mode, MaxChars: limits.MaxChars, MaxDepth: limits.MaxDepth, MaxNodes: limits.MaxNodes}
}

// inputJSON is the case input as JSON text.
func (c vectorCase) inputJSON(t *testing.T) []byte {
	t.Helper()
	if c.InputGen != nil {
		return jsonString(expandParts(t, *c.InputGen))
	}
	return c.Input
}

// expectedJSON is the expected output of the standard tier (the sync side) as JSON text.
func (c vectorCase) expectedJSON(t *testing.T) []byte {
	t.Helper()
	if len(c.Expected) > 0 {
		return c.Expected
	}
	if c.ExpectedGenSync != nil {
		return jsonString(expandParts(t, *c.ExpectedGenSync))
	}
	return c.ExpectedSync
}

// run redacts the JSON text `input` through the entry point its type selects and returns the
// output as JSON text. A string without a lone surrogate takes the text entry.
func run(t *testing.T, input []byte, opts Options) []byte {
	t.Helper()
	tree := parseTree(t, input)
	if tree.kind == kindString && !hasLoneSurrogate(tree.str) {
		out, _ := RedactText(unitsToString(tree.str), opts)
		return jsonString(decodeUTF8(out))
	}
	out, _, err := RedactJSON(input, opts)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVectorsStandardTier(t *testing.T) {
	for name, file := range loadVectors(t) {
		for _, c := range file.Cases {
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				got := run(t, c.inputJSON(t), c.options())
				if !sameValue(t, got, c.expectedJSON(t)) {
					t.Fatalf("output differs from the vector (%d bytes)", len(got))
				}
			})
		}
	}
}

func TestVectorsAreIdempotent(t *testing.T) {
	for name, file := range loadVectors(t) {
		for _, c := range file.Cases {
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				want := c.expectedJSON(t)
				got := run(t, want, Options{Mode: c.options().Mode})
				if !sameValue(t, got, want) {
					t.Fatal("redacting the expected output changed it")
				}
			})
		}
	}
}

func TestVectorFilesAreAllPresent(t *testing.T) {
	want := []string{
		"auth-headers", "base64", "entropy", "false-positives", "key-formats", "key-names",
		"keywords", "modes", "nested-json", "url-query",
	}
	loaded := loadVectors(t)
	if len(loaded) != len(want) {
		t.Fatalf("expected %d vector files, found %d", len(want), len(loaded))
	}
	for _, name := range want {
		if len(loaded[name].Cases) == 0 {
			t.Fatalf("vector file %s has no cases", name)
		}
	}
}

func TestVectorFilesMatchTheSpecDirectory(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "spec", "vectors"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		original := readFile(t, "..", "spec", "vectors", entry.Name())
		copied := readFile(t, "spec", "vectors", entry.Name())
		if string(original) != string(copied) {
			t.Fatalf("%s: the embedded copy differs from spec/vectors", entry.Name())
		}
	}
}
