package redaction

import (
	"encoding/json"
	"errors"
	"sort"
)

// scanner runs one rule kind over a text and returns its ranges in the order of its kind.
type scanner interface {
	scan(t *text) []span
}

type pipelineEntry struct {
	id      string
	scanner scanner
}

// engine is the interpreter: the loaded spec, compiled once at start-up.
type engine struct {
	spec         *loadedSpec
	placeholders *placeholders
	evidence     *evidence
	keys         *keyNames
	pipeline     []pipelineEntry
	full         []pipelineEntry
	letters      *letterTable
	whitespace   *unitSet
	skipKeys     [][]uint16
	failureIDs   map[string]bool
}

// builder compiles spec text; the first failure sticks and every later call is a no-op.
type builder struct {
	spec *loadedSpec
	err  error
}

func (b *builder) fail(err error) {
	if b.err == nil {
		b.err = err
	}
}

func (b *builder) pattern(template string) string {
	if b.err != nil {
		return ""
	}
	expanded, err := b.spec.expand(template)
	b.fail(err)
	return expanded
}

func (b *builder) class(template string) *unitSet {
	set, err := parseClass(b.pattern(template))
	if b.err == nil {
		b.fail(err)
	}
	return set
}

func (b *builder) searcher(template string) *searcher {
	found, err := newSearcher(b.pattern(template))
	if b.err == nil {
		b.fail(err)
	}
	return found
}

func (b *builder) anchored(template string) *anchored {
	found, err := newAnchored(b.pattern(template), "")
	if b.err == nil {
		b.fail(err)
	}
	return found
}

func (b *builder) classes(templates []string) []*unitSet {
	sets := make([]*unitSet, len(templates))
	for i, template := range templates {
		sets[i] = b.class(template)
	}
	return sets
}

func decodeRule(raw json.RawMessage, into any) error {
	if err := json.Unmarshal(raw, into); err != nil {
		return errSpecRejected
	}
	return nil
}

func newEngine(spec *loadedSpec) (*engine, error) {
	b := &builder{spec: spec}
	grammar := b.pattern(spec.rules.Patterns.Placeholder)
	if b.err != nil {
		return nil, b.err
	}
	found, err := newPlaceholders(spec, grammar)
	if err != nil {
		return nil, err
	}
	ids := spec.algorithms.RuleIDs
	failures := []string{ids.SizeLimit, ids.DepthLimit, ids.Circular, ids.Failed, ids.Error}
	e := &engine{spec: spec, placeholders: found, failureIDs: toSet(failures)}
	e.whitespace = b.class("[{{WS}}]")
	e.evidence = newEvidence(b, found, e.whitespace)
	e.keys = newKeyNames(&spec.keys, found)
	for _, key := range spec.keys.StructuralSkipKeys {
		e.skipKeys = append(e.skipKeys, decodeUTF8(key))
	}
	if e.letters, err = parseLetters(spec.algorithms.Letters.Ranges); err != nil {
		return nil, err
	}
	if e.pipeline, err = e.buildRules(b, spec.rules.Pipeline, e.standardKinds()); err != nil {
		return nil, err
	}
	if e.full, err = e.buildRules(b, spec.rules.Full, e.fullKinds()); err != nil {
		return nil, err
	}
	if b.err != nil {
		return nil, b.err
	}
	return e, nil
}

func asUnitLists(words []string) [][]uint16 {
	lists := make([][]uint16, len(words))
	for i, word := range words {
		lists[i] = decodeUTF8(word)
	}
	return lists
}

func newEvidence(b *builder, found *placeholders, whitespace *unitSet) *evidence {
	algorithms := &b.spec.algorithms
	trivial := algorithms.Trivial
	v := &evidence{
		quotes:       decodeUTF8(algorithms.Evidence.QuoteChars),
		classes:      b.classes(algorithms.Evidence.Classes),
		minClasses:   algorithms.Evidence.MinClasses,
		threshold:    algorithms.Evidence.EntropyThreshold,
		trivialWords: toSet(trivial.Words),
		wrapperInner: b.class(trivial.WrapperInner),
		docPrefixes:  asUnitLists(algorithms.DocPlaceholder.Prefixes),
		docSuffixes:  asUnitLists(algorithms.DocPlaceholder.Suffixes),
		docSeparator: b.class(algorithms.DocPlaceholder.Separator),
		whitespace:   whitespace,
		placeholders: found,
	}
	for _, mask := range trivial.MaskChars {
		v.maskChars = append(v.maskChars, decodeUTF8(mask)[0])
	}
	for _, pair := range trivial.Wrappers {
		v.wrappers = append(v.wrappers, [2]uint16{decodeUTF8(pair[0])[0], decodeUTF8(pair[1])[0]})
	}
	return v
}

type ruleHead struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type ruleBuilder func(*builder, json.RawMessage) (scanner, error)

// standardKinds are the rule kinds of the standard tier (`pipeline`); anything else in it stops the
// package at load time.
func (e *engine) standardKinds() map[string]ruleBuilder {
	return map[string]ruleBuilder{
		"regex":          e.newRegexRule,
		"dotted-token":   e.newDottedToken,
		"pem-blocks":     e.newPemBlocks,
		"cookie-lines":   e.newCookieLines,
		"auth-values":    e.newAuthValues,
		"keyword-pairs":  e.newKeywordPairs,
		"quoted-pairs":   e.newQuotedPairs,
		"unquoted-pairs": e.newUnquotedPairs,
		"query-values":   e.newQueryValues,
	}
}

// fullKinds are the rule kinds of the full tier (`full`).
func (e *engine) fullKinds() map[string]ruleBuilder {
	return map[string]ruleBuilder{
		"regex":          e.newRegexRule,
		"token":          e.newTokenRule,
		"dash-chain":     e.newDashChain,
		"sendgrid-key":   e.newSendgridKey,
		"pem-key":        e.newPemKey,
		"credential-uri": e.newCredentialURI,
	}
}

func (e *engine) buildRules(
	b *builder, raws []json.RawMessage, kinds map[string]ruleBuilder,
) ([]pipelineEntry, error) {
	rules := make([]pipelineEntry, 0, len(raws))
	for _, raw := range raws {
		var head ruleHead
		if err := decodeRule(raw, &head); err != nil {
			return nil, err
		}
		build, known := kinds[head.Kind]
		if !known {
			return nil, errors.New("redaction: unknown rule kind in the spec")
		}
		rule, err := build(b, raw)
		if err != nil {
			return nil, err
		}
		rules = append(rules, pipelineEntry{id: head.ID, scanner: rule})
	}
	return rules, nil
}

// detect is the standard tier on a whole text: every rule in pipeline order, hits merged.
func (e *engine) detect(t *text) []hit {
	var hits []hit
	for _, entry := range e.pipeline {
		for _, found := range entry.scanner.scan(t) {
			hits = append(hits, hit{id: entry.id, start: found.start, end: found.end})
		}
	}
	return mergeHits(hits)
}

// mergeHits sorts by start (stable: equal starts keep pipeline order) and folds overlapping or
// touching hits into the earliest one (SPEC 7).
func mergeHits(hits []hit) []hit {
	sorted := append([]hit(nil), hits...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].start < sorted[j].start })
	merged := make([]hit, 0, len(sorted))
	for _, next := range sorted {
		last := len(merged) - 1
		if last >= 0 && next.start <= merged[last].end {
			merged[last].end = max(merged[last].end, next.end)
			continue
		}
		merged = append(merged, next)
	}
	return merged
}

// splice replaces every hit (already merged) by its read placeholder.
func (e *engine) splice(units []uint16, hits []hit) []uint16 {
	out := make([]uint16, 0, len(units))
	cursor := 0
	for _, found := range hits {
		out = append(out, units[cursor:found.start]...)
		out = append(out, e.placeholders.readUnits(found.id)...)
		cursor = found.end
	}
	return append(out, units[cursor:]...)
}
