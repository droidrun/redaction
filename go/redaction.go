// Package redaction finds secrets in text and JSON values and replaces them with placeholders
// such as `[REDACTED:generic-keyword]`. It is the Go interpreter of the language-neutral spec in
// spec/ of the same repository and gives the same output as the TypeScript package, in both tiers:
// the standard tier (the default) and the full tier (the standard rules plus the ported secretlint
// preset). In the default Strict mode a call never returns text that was not scanned.
package redaction

import (
	"errors"
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

// Tier selects the rule set. A value other than TierStandard is read as TierFull: an out-of-range
// tier fails toward more redaction.
type Tier int

const (
	// TierStandard runs the standard rules. It is the zero value.
	TierStandard Tier = iota
	// TierFull runs the standard rules and the full-tier rules (key formats, connection strings,
	// private keys, ...). The full-tier rules see the first 2,000,000 units of a text, in windows.
	TierFull
)

// Options are the parameters of a call. A nil limit is the spec default; an explicit limit is
// used as given, so Limit(0) is a limit of zero (as in the TypeScript package).
//
// The full tier in Compat mode has no length, depth or node limit (SPEC 9.4, as in the TypeScript
// package), so an explicit MaxChars, MaxDepth or MaxNodes together with TierFull and Compat is an
// error and not silently ignored: RedactText returns `[REDACTED:error]` with Result.Err
// `invalid-options`, RedactJSON returns the JSON string `"[REDACTED:error]"`, the same Result and
// ErrInvalidOptions. Use Strict for limits.
type Options struct {
	Tier Tier
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

// tier is the tier a call runs: TierStandard, or TierFull for every other value.
func (o Options) tier() Tier {
	if o.Tier == TierStandard {
		return TierStandard
	}
	return TierFull
}

// hasInvalidLimits is true for the full tier in compat mode with an explicit limit: that tier has
// no limits, so the option cannot be honoured.
func (o Options) hasInvalidLimits() bool {
	hasLimit := o.MaxChars != nil || o.MaxDepth != nil || o.MaxNodes != nil
	return hasLimit && o.tier() == TierFull && o.Mode == Compat
}

// invalidOptionsClass is the Result.Err class of options that cannot be honoured.
const invalidOptionsClass = "invalid-options"

// ErrInvalidOptions is returned by RedactJSON for options that cannot be honoured (an explicit
// limit in the full tier in compat mode). It never quotes the input.
var ErrInvalidOptions = errors.New("redaction: invalid options")

// invalidOptionsResult is what a call with invalid options reports: the `error` placeholder is the
// whole output, and the class says why.
func (e *engine) invalidOptionsResult() (placeholder string, result Result) {
	rec := newRecorder(e)
	rec.add(e.spec.algorithms.RuleIDs.Error)
	result = rec.result()
	result.Err = invalidOptionsClass
	return e.placeholders.read(e.spec.algorithms.RuleIDs.Error), result
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
	// `redaction-failed`, `error`, or `invalid-options` for options that cannot be honoured), or
	// empty. The output is safe either way: the placeholder is in it.
	Err string
}

// recorder counts hits per rule id, in the order the ids first occurred, and keeps the class of
// the first fail-closed event.
type recorder struct {
	e       *engine
	hits    []RuleCount
	failure string
}

func newRecorder(e *engine) *recorder {
	return &recorder{e: e}
}

func (r *recorder) add(ruleID string) {
	if r.failure == "" && r.e.failureIDs[ruleID] {
		r.failure = ruleID
	}
	for i := range r.hits {
		if r.hits[i].RuleID == ruleID {
			r.hits[i].Count++
			return
		}
	}
	r.hits = append(r.hits, RuleCount{RuleID: ruleID, Count: 1})
}

// fail records the class of a fail-closed event without counting a hit (the event may be part of a
// merged hit that carries another rule id).
func (r *recorder) fail(ruleID string) {
	if r.failure == "" {
		r.failure = ruleID
	}
}

func (r *recorder) addHits(hits []hit) {
	for _, found := range hits {
		r.add(found.id)
	}
}

func (r *recorder) result() Result {
	return Result{Hits: r.hits, Err: r.failure}
}

// scanMode says how a text or a leaf is scanned: which tier, and what a failure or a size limit does.
type scanMode struct {
	tier     Tier
	strict   bool
	maxChars int
}

func (e *engine) scanMode(opts Options, lim limits) scanMode {
	return scanMode{tier: opts.tier(), strict: opts.Mode != Compat, maxChars: lim.maxChars}
}

// scan scans a text of units in the given mode and returns it with the hits spliced.
func (e *engine) scan(units []uint16, mode scanMode, rec *recorder) []uint16 {
	switch {
	case mode.tier == TierFull && mode.strict:
		return e.redactFullStrict(units, mode.maxChars, rec)
	case mode.tier == TierFull:
		return e.redactFullCompat(units, rec)
	}
	return e.redactUnits(units, rec)
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

// RedactText redacts one text. Input that is not valid UTF-8 is read with each invalid byte as
// U+FFFD, and the output holds that U+FFFD. It never panics: an internal failure gives
// `[REDACTED:redaction-failed]` (standard tier) or `[REDACTED:error]` (full tier).
func RedactText(s string, opts Options) (string, Result) {
	e := theEngine
	if opts.hasInvalidLimits() {
		return e.invalidOptionsResult()
	}
	rec := newRecorder(e)
	mode := e.scanMode(opts, e.limits(opts))
	return e.redactTextSafely(s, mode, rec), rec.result()
}

func (e *engine) redactTextSafely(s string, mode scanMode, rec *recorder) (out string) {
	defer func() {
		if recover() != nil {
			failed := e.spec.algorithms.RuleIDs.Failed
			rec.add(failed)
			out = e.placeholders.read(failed)
		}
	}()
	return e.redactText(s, mode, rec)
}

// exceedsChars is true when the text certainly or exactly holds more than maxChars units. A unit
// is at most three bytes, so a longer string is refused before it is decoded.
func exceedsChars(s string, maxChars int) bool {
	return maxChars < unbounded/3 && len(s) > 3*maxChars
}

func (e *engine) redactText(s string, mode scanMode, rec *recorder) string {
	sizeLimit := e.spec.algorithms.RuleIDs.SizeLimit
	if exceedsChars(s, mode.maxChars) {
		rec.add(sizeLimit)
		return e.placeholders.read(sizeLimit)
	}
	units := decodeUTF8(s)
	if len(units) > mode.maxChars {
		rec.add(sizeLimit)
		return e.placeholders.read(sizeLimit)
	}
	out := e.scan(units, mode, rec)
	if len(rec.hits) == 0 && utf8.ValidString(s) {
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
// The full tier in compat mode has none (SPEC 9.4).
func (e *engine) limits(opts Options) limits {
	if opts.tier() == TierFull && opts.Mode == Compat {
		return limits{maxChars: unbounded, maxDepth: unbounded, maxNodes: unbounded}
	}
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

// RedactJSON redacts a JSON value with the rules of the tier and the key-name rules: a string leaf
// is scanned, a string under a secret-named key is replaced, and so is a number under a singular
// secret key. Object keys come out in ECMAScript order (integer-like keys first); for a repeated
// key the last value wins; keys that redact to the same key keep their values, the first under the
// plain key and the others under `[REDACTED:rule#2]`, `#3`, ... (inside the brackets); numbers are written as ECMAScript writes the nearest double. The
// output is compact JSON.
//
// Input that is not one JSON value gives ErrInvalidJSON together with the redaction of the raw
// input as a text (the same as RedactText gives, with its Result): the output is never the input
// and never nil, so a caller that logs the output on error cannot leak.
//
// The limits are enforced while the input is read: what the walk would cut is only checked for
// syntax, so memory stays proportional to the limits (a node costs about 100 bytes) and not to the
// size of the input.
func RedactJSON(data []byte, opts Options) ([]byte, Result, error) {
	e := theEngine
	if opts.hasInvalidLimits() {
		placeholder, result := e.invalidOptionsResult()
		return appendString(nil, decodeUTF8(placeholder)), result, ErrInvalidOptions
	}
	lim := e.limits(opts)
	parsing := parseLimits{
		nodes:        lim.maxNodes,
		depth:        lim.maxDepth,
		chars:        lim.maxChars,
		elideStrings: opts.Mode != Compat,
	}
	root, err := parseJSON(data, parsing)
	if err != nil {
		text, result := RedactText(string(data), opts)
		return []byte(text), result, ErrInvalidJSON
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
		mode:     e.scanMode(opts, lim),
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
