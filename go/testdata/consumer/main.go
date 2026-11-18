// Command consumer builds against the package from outside its module and runs the conformance
// vectors through the public API only (`go run .` in this directory). It exits 1 on a difference.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	redaction "github.com/droidrun/redaction/go"
)

type vector struct {
	Name         string                                      `json:"name"`
	Input        json.RawMessage                             `json:"input"`
	Mode         string                                      `json:"mode"`
	Opts         struct{ MaxChars, MaxDepth, MaxNodes *int } `json:"opts"`
	Expected     json.RawMessage                             `json:"expected"`
	ExpectedSync json.RawMessage                             `json:"expectedSync"`
}

func (v vector) options() redaction.Options {
	opts := redaction.Options{
		Mode: redaction.Compat, MaxChars: v.Opts.MaxChars, MaxDepth: v.Opts.MaxDepth, MaxNodes: v.Opts.MaxNodes,
	}
	if v.Mode == "strict" {
		opts.Mode = redaction.Strict
	}
	return opts
}

func (v vector) expected() []byte {
	if v.Expected != nil {
		return v.Expected
	}
	return v.ExpectedSync
}

func compact(pretty []byte) []byte {
	var out bytes.Buffer
	if err := json.Compact(&out, pretty); err != nil {
		panic(err)
	}
	return out.Bytes()
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
			got, _, err := redaction.RedactJSON(c.Input, c.options())
			total++
			if err != nil || !bytes.Equal(got, compact(c.expected())) {
				differing++
				fmt.Println("DIFF", c.Name)
			}
		}
	}
	text, _ := redaction.RedactText("password=Zq9abcDEF123ghi_x", redaction.Options{})
	fmt.Printf("public API: %d vector cases, %d differ; %s\n", total, differing, text)
	if differing > 0 || total < 100 || text != "password=[REDACTED:generic-keyword]" {
		os.Exit(1)
	}
}
