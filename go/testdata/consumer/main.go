// Command consumer builds against the package from outside its module and runs the conformance
// vectors through the public API only (`go run .` in this directory). It exits 1 on a difference.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	redaction "github.com/droidrun/redaction/go"
)

type vector struct {
	Name          string                                      `json:"name"`
	Input         json.RawMessage                             `json:"input"`
	Mode          string                                      `json:"mode"`
	Opts          struct{ MaxChars, MaxDepth, MaxNodes *int } `json:"opts"`
	Expected      json.RawMessage                             `json:"expected"`
	ExpectedSync  json.RawMessage                             `json:"expectedSync"`
	ExpectedAsync json.RawMessage                             `json:"expectedAsync"`
}

func (v vector) options(tier redaction.Tier) redaction.Options {
	opts := redaction.Options{
		Tier: tier, Mode: redaction.Compat,
		MaxChars: v.Opts.MaxChars, MaxDepth: v.Opts.MaxDepth, MaxNodes: v.Opts.MaxNodes,
	}
	if v.Mode == "strict" {
		opts.Mode = redaction.Strict
	}
	return opts
}

// expected is the expected output of a tier: the sync side is the standard tier, the async side the
// full tier.
func (v vector) expected(tier redaction.Tier) []byte {
	switch {
	case v.Expected != nil:
		return v.Expected
	case tier == redaction.TierFull:
		return v.ExpectedAsync
	}
	return v.ExpectedSync
}

// sameValue compares two JSON texts as values (the vectors write strings with \u escapes).
func sameValue(a []byte, b []byte) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

func main() {
	files, err := filepath.Glob(filepath.Join("..", "..", "spec", "vectors", "*.json"))
	if err != nil || len(files) == 0 {
		fmt.Println("no vector files")
		os.Exit(1)
	}
	total, differing := 0, 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		var file struct{ Cases []vector }
		if err := json.Unmarshal(raw, &file); err != nil {
			panic(err)
		}
		for _, c := range file.Cases {
			if c.Input == nil {
				continue // generated inputs are covered by the package tests
			}
			for _, tier := range []redaction.Tier{redaction.TierStandard, redaction.TierFull} {
				got, _, err := redaction.RedactJSON(c.Input, c.options(tier))
				total++
				if err != nil || !sameValue(got, c.expected(tier)) {
					differing++
					fmt.Println("DIFF", c.Name)
				}
			}
		}
	}
	text, _ := redaction.RedactText("password=Zq9abcDEF123ghi_x", redaction.Options{})
	token := "npm_" + strings.Repeat("A", 36)
	full, _ := redaction.RedactText(token, redaction.Options{Tier: redaction.TierFull})
	fmt.Printf("public API: %d vector runs (both tiers), %d differ; %s %s\n", total, differing, text, full)
	isRight := text == "password=[REDACTED:generic-keyword]" && full == "[REDACTED:npm]"
	if differing > 0 || total < 300 || !isRight {
		os.Exit(1)
	}
}
