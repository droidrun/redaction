// Package redaction finds secrets in text and JSON values and replaces them with placeholders
// such as `[REDACTED:generic-keyword]`. It is the Go interpreter of the language-neutral spec in
// spec/ of the same repository and gives the same output as the TypeScript package.
//
// Only the standard tier exists in this version. Output of a call never contains text that was
// not scanned in the default Strict mode.
package redaction

import (
	"unicode/utf16"
	"unicode/utf8"
)

// Mode selects how failures and limits are handled.
type Mode int

const (
	// Strict never returns text that was not scanned: a cap, a limit or an internal failure gives
	// a placeholder. It is the zero value.
	Strict Mode = iota
	// Compat reproduces the TypeScript package v0.2.0 for the standard tier.
	Compat
)

// Options are the parameters of a call. A nil limit is the spec default; an explicit limit is
// used as given, so Limit(0) is a limit of zero (as in the TypeScript package).
type Options struct {
	Mode Mode
	// SkipKeys replaces the default skip keys (`type`, `id`): a primitive value under such a key
	// is not replaced by key context. A nil slice keeps the default; an empty one skips nothing.
	SkipKeys []string
	// MaxDepth is the deepest container level that is walked (JSON only).
	MaxDepth *int
	// MaxNodes is the number of values that are visited (JSON only).
	MaxNodes *int
	// MaxChars is the number of UTF-16 units of a text, or in total of a JSON value.
	MaxChars *int
}

// Limit returns a pointer to n, for the limit fields of Options.
func Limit(n int) *int {
	return &n
}

// RuleCount is the number of hits of one rule. Ranges are not exposed: they would reveal lengths.
type RuleCount struct {
	RuleID string
	Count  int
}

// Result is what a call reports about its hits, never the matched text.
type Result struct {
	// Hits counts the hits per rule id, in the order the ids first occurred.
	Hits []RuleCount
	// Err is the class of the first fail-closed event of the call (`size-limit`, `depth-limit`,
	// `redaction-failed`), or empty. The output is safe either way: the placeholder is in it.
	Err string
}

// recorder counts hits per rule id.
type recorder struct {
	failureIDs map[string]bool
	order      []string
	counts     map[string]int
	failure    string
}

func newRecorder(e *engine) *recorder {
	ids := e.spec.algorithms.RuleIDs
	failures := []string{ids.SizeLimit, ids.DepthLimit, ids.Circular, ids.Failed, ids.Error}
	return &recorder{failureIDs: toSet(failures), counts: make(map[string]int)}
}

func (r *recorder) add(ruleID string) {
	if r.counts[ruleID] == 0 {
		r.order = append(r.order, ruleID)
	}
	r.counts[ruleID]++
	if r.failure == "" && r.failureIDs[ruleID] {
		r.failure = ruleID
	}
}

func (r *recorder) addHits(hits []hit) {
	for _, found := range hits {
		r.add(found.id)
	}
}

func (r *recorder) result() Result {
	result := Result{Err: r.failure}
	for _, ruleID := range r.order {
		result.Hits = append(result.Hits, RuleCount{RuleID: ruleID, Count: r.counts[ruleID]})
	}
	return result
}

// redactUnits scans a text of units with the standard rules and returns it with the hits spliced.
func (e *engine) redactUnits(units []uint16, rec *recorder) []uint16 {
	if len(units) < e.spec.algorithms.Text.MinScanLength {
		return units
	}
	hits := e.detect(newText(units))
	rec.addHits(hits)
	return e.splice(units, hits)
}

func unitsToString(units []uint16) string {
	return string(utf16.Decode(units))
}

func orDefault(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

// RedactText redacts one text with the standard tier. Input that is not valid UTF-8 is read with
// each invalid byte as U+FFFD, and the output holds that U+FFFD. It never panics: an internal
// failure gives `[REDACTED:redaction-failed]`.
func RedactText(s string, opts Options) (string, Result) {
	e := theEngine
	rec := newRecorder(e)
	return e.redactTextSafely(s, e.limits(opts).maxChars, rec), rec.result()
}

func (e *engine) redactTextSafely(s string, maxChars int, rec *recorder) (out string) {
	defer func() {
		if recover() != nil {
			failed := e.spec.algorithms.RuleIDs.Failed
			rec.add(failed)
			out = e.placeholders.read(failed)
		}
	}()
	return e.redactText(s, maxChars, rec)
}

// exceedsChars is true when the text certainly or exactly holds more than maxChars units. A unit
// is at most three bytes, so a longer string is refused before it is decoded.
func exceedsChars(s string, maxChars int) bool {
	return maxChars < unbounded/3 && len(s) > 3*maxChars
}

func (e *engine) redactText(s string, maxChars int, rec *recorder) string {
	sizeLimit := e.spec.algorithms.RuleIDs.SizeLimit
	if exceedsChars(s, maxChars) {
		rec.add(sizeLimit)
		return e.placeholders.read(sizeLimit)
	}
	units := decodeUTF8(s)
	if len(units) > maxChars {
		rec.add(sizeLimit)
		return e.placeholders.read(sizeLimit)
	}
	out := e.redactUnits(units, rec)
	if len(rec.order) == 0 && utf8.ValidString(s) {
		return s
	}
	return unitsToString(out)
}

// IsSecretKeyName reports whether an object key names a secret (`apiKey`, `x-auth-token`,
// `Set-Cookie`, `pin`, `tokens`).
func IsSecretKeyName(key string) bool {
	return theEngine.keys.isSecretKeyName(decodeUTF8(key))
}

type limits struct {
	maxChars int
	maxDepth int
	maxNodes int
}

// limits are the limits of a call: the options of the caller over the spec defaults of the mode.
func (e *engine) limits(opts Options) limits {
	defaults := limits{
		e.spec.algorithms.Strict.MaxChars,
		e.spec.algorithms.Strict.MaxDepth,
		e.spec.algorithms.Strict.MaxNodes,
	}
	if opts.Mode == Compat {
		sync := e.spec.algorithms.Sync
		defaults = limits{sync.MaxChars, sync.MaxDepth, sync.MaxNodes}
	}
	return limits{
		maxChars: orDefault(opts.MaxChars, defaults.maxChars),
		maxDepth: orDefault(opts.MaxDepth, defaults.maxDepth),
		maxNodes: orDefault(opts.MaxNodes, defaults.maxNodes),
	}
}

// RedactJSON redacts a JSON value with the standard tier and the key-name rules: a string leaf
// is scanned, a string under a secret-named key is replaced, and so is a number under a singular
// secret key. Object keys come out in ECMAScript order (integer-like keys first); for a repeated
// key the last value wins; numbers are written as ECMAScript writes the nearest double. The
// output is compact JSON. Input that is not one JSON value gives ErrInvalidJSON.
//
// The limits are enforced while the input is read: what the walk would cut is only checked for
// syntax, so memory stays proportional to the limits (a node costs about 100 bytes) and not to the
// size of the input.
func RedactJSON(data []byte, opts Options) ([]byte, Result, error) {
	e := theEngine
	lim := e.limits(opts)
	parsing := parseLimits{
		nodes:        lim.maxNodes,
		depth:        lim.maxDepth,
		chars:        lim.maxChars,
		elideStrings: opts.Mode != Compat,
	}
	root, err := parseJSON(data, parsing)
	if err != nil {
		return nil, Result{}, ErrInvalidJSON
	}
	rec := newRecorder(e)
	out := e.walkSafely(root, opts, lim, rec)
	return marshal(out), rec.result(), nil
}

func (e *engine) walkSafely(root *node, opts Options, lim limits, rec *recorder) (out *node) {
	defer func() {
		if recover() != nil {
			failed := e.spec.algorithms.RuleIDs.Failed
			rec.add(failed)
			out = stringNode(e.placeholders.readUnits(failed))
		}
	}()
	return e.newWalker(opts, lim, rec).walk(root)
}

func (e *engine) newWalker(opts Options, lim limits, rec *recorder) *walker {
	w := &walker{
		e:        e,
		strict:   opts.Mode != Compat,
		nodes:    lim.maxNodes,
		chars:    lim.maxChars,
		maxDepth: lim.maxDepth,
		skip:     e.skipKeys,
		rec:      rec,
	}
	if opts.SkipKeys != nil {
		w.skip = nil
		for _, key := range opts.SkipKeys {
			w.skip = append(w.skip, decodeUTF8(key))
		}
	}
	return w
}
