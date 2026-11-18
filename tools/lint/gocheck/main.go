// gocheck compiles every pattern with Go's regexp (RE2). It reads a JSON list from stdin.
package main

import (
	"encoding/json"
	"os"
	"regexp"
)

type item struct {
	Where  string `json:"where"`
	Source string `json:"source"`
}

type failure struct {
	Where string `json:"where"`
	Error string `json:"error"`
}

func main() {
	var items []item
	if err := json.NewDecoder(os.Stdin).Decode(&items); err != nil {
		os.Exit(2)
	}
	failures := []failure{}
	for _, entry := range items {
		if _, err := regexp.Compile(entry.Source); err != nil {
			failures = append(failures, failure{Where: entry.Where, Error: err.Error()})
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(failures)
}
