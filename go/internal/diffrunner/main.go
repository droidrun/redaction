// Command diffrunner is the Go runner of the cross-language differential test (tools/diff).
// It reads one request per line on stdin and writes one response per line on stdout:
//
//	request:  {"id", "kind": "text"|"json", "tier", "mode", "opts", "input"}
//	response: {"id", "out", "hits": [[ruleId, count]...], "error"}
//
// `input` stays raw JSON: a text that holds a
// lone surrogate cannot be a Go string, so it goes through the JSON entry point as a JSON string,
// the way the golden replay does it.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"

	redaction "github.com/droidrun/redaction/go"
)

type request struct {
	ID    json.RawMessage `json:"id"`
	Kind  string          `json:"kind"`
	Tier  string          `json:"tier"`
	Mode  string          `json:"mode"`
	Opts  requestOpts     `json:"opts"`
	Input json.RawMessage `json:"input"`
}

type requestOpts struct {
	MaxChars *int     `json:"maxChars"`
	MaxDepth *int     `json:"maxDepth"`
	MaxNodes *int     `json:"maxNodes"`
	SkipKeys []string `json:"skipKeys"`
	PII      bool     `json:"pii"`
}

type response struct {
	ID   json.RawMessage `json:"id"`
	Out  json.RawMessage `json:"out"`
	Hits [][]any         `json:"hits"`
	// Error is the class of a fail-closed event of the library (informational, not compared).
	Error *string `json:"error"`
	// Crash is an exception of the runner or an unexpected failure of the call; the driver fails on it.
	Crash *string `json:"crash"`
}

// surrogateEscape matches a JSON escape of a UTF-16 surrogate unit.
var surrogateEscape = regexp.MustCompile(`\\u[dD][89a-fA-F][0-9a-fA-F]{2}`)

func options(req request) redaction.Options {
	opts := redaction.Options{
		MaxChars: req.Opts.MaxChars,
		MaxDepth: req.Opts.MaxDepth,
		MaxNodes: req.Opts.MaxNodes,
		SkipKeys: req.Opts.SkipKeys,
		PII:      req.Opts.PII,
	}
	if req.Mode == "compat" {
		opts.Mode = redaction.Compat
	}
	if req.Tier == "full" {
		opts.Tier = redaction.TierFull
	}
	return opts
}

func counts(result redaction.Result) [][]any {
	hits := make([][]any, 0, len(result.Hits))
	for _, hit := range result.Hits {
		hits = append(hits, []any{hit.RuleID, hit.Count})
	}
	return hits
}

func marshalString(s string) []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(s)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func handle(req request) (resp response) {
	defer func() {
		if recovered := recover(); recovered != nil {
			resp = crash(req, "panic")
		}
	}()
	opts := options(req)
	var out []byte
	var result redaction.Result
	switch {
	case req.Kind == "text" && !surrogateEscape.Match(req.Input):
		var text string
		if err := json.Unmarshal(req.Input, &text); err != nil {
			return crash(req, fmt.Sprintf("%T", err))
		}
		redacted, res := redaction.RedactText(text, opts)
		out, result = marshalString(redacted), res
	default:
		var err error
		out, result, err = redaction.RedactJSON(req.Input, opts)
		if err != nil {
			return crash(req, fmt.Sprintf("%T", err))
		}
	}
	resp = response{ID: req.ID, Out: out, Hits: counts(result)}
	if result.Err != "" {
		resp.Error = &result.Err
	}
	return resp
}

func crash(req request, class string) response {
	return response{ID: req.ID, Out: json.RawMessage("null"), Hits: [][]any{}, Crash: &class}
}

func main() {
	writer := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer writer.Flush()
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	reader := bufio.NewReaderSize(os.Stdin, 1<<20)
	for {
		line, err := reader.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var req request
			if jsonErr := json.Unmarshal(line, &req); jsonErr != nil {
				fmt.Fprintln(os.Stderr, "bad request line")
				os.Exit(2)
			}
			_ = encoder.Encode(handle(req))
			if reader.Buffered() == 0 {
				_ = writer.Flush() // nothing more to read now: let the driver see the answers
			}
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "read failed")
			os.Exit(2)
		}
	}
}
