package redaction

import (
	"encoding/json"
	"errors"
)

// partKind is one kind of part of a token shape (SPEC 4.11).
type partKind int

const (
	partLiteral partKind = iota
	partAlternatives
	partFixedRun
	partVariableRun
	partOptional
)

type partSpec struct {
	Lit      *string    `json:"lit"`
	Alt      []string   `json:"alt"`
	RunClass string     `json:"runClass"`
	Min      int        `json:"min"`
	Max      int        `json:"max"`
	Tails    []string   `json:"tails"`
	Opt      []partSpec `json:"opt"`
}

type tokenPart struct {
	kind  partKind
	lits  [][]uint16 // a literal (one entry) or the alternatives
	set   *unitSet
	min   int
	max   int
	tails [][]uint16
	inner []tokenPart
	memo  int // the index of the run memory of a variable run
}

type tokenSpec struct {
	LetterGuard bool       `json:"letterGuard"`
	Parts       []partSpec `json:"parts"`
	NotAfter    string     `json:"notAfter"`
	Check       string     `json:"check"`
	CheckFrom   int        `json:"checkFrom"`
}

// tokenRule is SPEC 4.11: a key format of literals and runs, an optional letter guard in front and
// a class that must not follow, matched without backtracking.
type tokenRule struct {
	starts      []string
	letterGuard bool
	letters     *letterTable
	parts       []tokenPart
	memos       int
	notAfter    *unitSet
	check       func([]uint16) bool
	checkFrom   int
}

var errUnknownCheck = errors.New("redaction: unknown check in the spec")

// tokenChecks are the checks a token rule may name; an unknown name stops the package at load time.
var tokenChecks = map[string]func([]uint16) bool{"base64-json": isBase64JSON}

type tokenCompiler struct {
	b     *builder
	memos int
}

func (c *tokenCompiler) literals(words []string) [][]uint16 {
	units := make([][]uint16, len(words))
	for i, word := range words {
		units[i] = decodeUTF8(word)
	}
	return units
}

func (c *tokenCompiler) part(spec partSpec) tokenPart {
	switch {
	case spec.Lit != nil:
		return tokenPart{kind: partLiteral, lits: c.literals([]string{*spec.Lit})}
	case spec.Alt != nil:
		return tokenPart{kind: partAlternatives, lits: c.literals(spec.Alt)}
	case spec.Opt != nil:
		return tokenPart{kind: partOptional, inner: c.parts(spec.Opt)}
	}
	run := tokenPart{
		set: c.b.class(spec.RunClass), min: spec.Min, max: spec.Max, tails: c.literals(spec.Tails),
	}
	if spec.Min == spec.Max && len(spec.Tails) == 0 {
		run.kind = partFixedRun
		return run
	}
	run.kind = partVariableRun
	run.memo = c.memos
	c.memos++
	return run
}

func (c *tokenCompiler) parts(specs []partSpec) []tokenPart {
	parts := make([]tokenPart, len(specs))
	for i, spec := range specs {
		parts[i] = c.part(spec)
	}
	return parts
}

func (e *engine) newTokenRule(b *builder, raw json.RawMessage) (scanner, error) {
	var spec tokenSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	compiler := &tokenCompiler{b: b}
	rule := &tokenRule{
		letterGuard: spec.LetterGuard,
		letters:     e.letters,
		parts:       compiler.parts(spec.Parts),
		checkFrom:   spec.CheckFrom,
	}
	rule.memos = compiler.memos
	if spec.NotAfter != "" {
		rule.notAfter = b.class(spec.NotAfter)
	}
	if spec.Check != "" {
		rule.check = tokenChecks[spec.Check]
		if rule.check == nil {
			return nil, errUnknownCheck
		}
	}
	first := spec.Parts[0]
	switch {
	case first.Lit != nil:
		rule.starts = []string{*first.Lit}
	case first.Alt != nil:
		rule.starts = first.Alt
	default:
		return nil, errors.New("redaction: a token shape starts with a literal")
	}
	return rule, b.err
}

const matchFailed = -1

// continuation is what has to match after an optional group: the rest of the parts it sits in,
// then the rest of the parts around that.
type continuation struct {
	parts []tokenPart
	index int
	next  *continuation
}

// tokenScan is the state of one scan of one text: the run memories, one per variable-run part.
type tokenScan struct {
	rule  *tokenRule
	t     *text
	memos []runMemo
}

func (s *tokenScan) literalAt(lits [][]uint16, position int) int {
	for _, literal := range lits {
		if hasUnitsAt(s.t.units, literal, position) {
			return position + len(literal)
		}
	}
	return matchFailed
}

func (s *tokenScan) fixedRun(part *tokenPart, position int) int {
	if position+part.min > len(s.t.units) {
		return matchFailed
	}
	for at := position; at < position+part.min; at++ {
		if !part.set.has(s.t.units[at]) {
			return matchFailed
		}
	}
	return position + part.min
}

// tailOf is the first tail (list order) the run [position, end) ends with.
func (s *tokenScan) tailOf(part *tokenPart, position int, end int) ([]uint16, bool) {
	for _, tail := range part.tails {
		if end-position >= len(tail) && hasUnitsAt(s.t.units, tail, end-len(tail)) {
			return tail, true
		}
	}
	return nil, false
}

// variableRun is the maximal run of the class; a tail the run ends with is part of the run but
// not counted.
func (s *tokenScan) variableRun(part *tokenPart, position int) int {
	end := s.memos[part.memo].end(s.t.units, part.set, position)
	counted := end - position
	if len(part.tails) > 0 {
		tail, found := s.tailOf(part, position, end)
		if !found {
			return matchFailed
		}
		counted -= len(tail)
	}
	if counted < part.min || counted > part.max {
		return matchFailed
	}
	return end
}

// match runs the parts from `position`, then what comes after them (`next`), then the class that
// must not follow. An optional group is tried first and skipped when it, or what follows it, fails.
func (s *tokenScan) match(parts []tokenPart, index int, position int, next *continuation) int {
	for ; index < len(parts); index++ {
		part := &parts[index]
		switch part.kind {
		case partLiteral, partAlternatives:
			position = s.literalAt(part.lits, position)
		case partFixedRun:
			position = s.fixedRun(part, position)
		case partVariableRun:
			position = s.variableRun(part, position)
		case partOptional:
			after := &continuation{parts: parts, index: index + 1, next: next}
			if end := s.match(part.inner, 0, position, after); end != matchFailed {
				return end
			}
			continue
		}
		if position == matchFailed {
			return matchFailed
		}
	}
	if next != nil {
		return s.match(next.parts, next.index, position, next.next)
	}
	if s.blocksAfter(position) {
		return matchFailed
	}
	return position
}

// blocksAfter: the unit at `position` is in the class that must not follow a token.
func (s *tokenScan) blocksAfter(position int) bool {
	if s.rule.notAfter == nil || position >= len(s.t.units) {
		return false
	}
	return s.rule.notAfter.has(s.t.units[position])
}

func (r *tokenRule) scan(t *text) []span {
	state := &tokenScan{rule: r, t: t, memos: make([]runMemo, r.memos)}
	finder := newStarts(t, r.starts)
	var found []span
	from := 0
	for start := finder.next(from); start != startNone; start = finder.next(from) {
		from = start + 1
		if r.letterGuard && !r.letters.passesGuard(t.units, start) {
			continue
		}
		end := state.match(r.parts, 0, start, nil)
		if end == matchFailed {
			continue
		}
		from = end
		if r.check == nil || r.check(t.units[start+r.checkFrom:end]) {
			found = append(found, span{start, end})
		}
	}
	return found
}

type dashChainSpec struct {
	Leads        []string `json:"leads"`
	Separator    string   `json:"separator"`
	SegmentClass string   `json:"segmentClass"`
	WordClass    string   `json:"wordClass"`
	MaxSegment   int      `json:"maxSegment"`
	MinSegments  int      `json:"minSegments"`
}

// dashChain is SPEC 4.12: Slack tokens, a lead and runs of alphanumerics joined by single dashes.
type dashChain struct {
	leads       []string
	leadUnits   [][]uint16
	separator   uint16
	segment     *unitSet
	word        *unitSet
	maxSegment  int
	minSegments int
}

func (e *engine) newDashChain(b *builder, raw json.RawMessage) (scanner, error) {
	var spec dashChainSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	rule := &dashChain{
		leads:       spec.Leads,
		separator:   decodeUTF8(spec.Separator)[0],
		segment:     b.class(spec.SegmentClass),
		word:        b.class(spec.WordClass),
		maxSegment:  spec.MaxSegment,
		minSegments: spec.MinSegments,
	}
	for _, lead := range spec.Leads {
		rule.leadUnits = append(rule.leadUnits, decodeUTF8(lead))
	}
	return rule, b.err
}

// chainEnd is the end of the last run that may end the token that starts its chain at
// `afterLead`, or -1.
func (d *dashChain) chainEnd(units []uint16, memo *runMemo, afterLead int) int {
	var ends []int
	for position := afterLead; ; {
		end := memo.end(units, d.segment, position)
		length := end - position
		if length < 1 || length > d.maxSegment {
			break
		}
		ends = append(ends, end)
		if end >= len(units) || units[end] != d.separator {
			break
		}
		position = end + 1
	}
	used := len(ends)
	if used > 0 && d.word.hasAt(units, ends[used-1]) {
		used--
	}
	if used < d.minSegments {
		return -1
	}
	return ends[used-1]
}

func (d *dashChain) scan(t *text) []span {
	var memo runMemo
	finder := newStarts(t, d.leads)
	var found []span
	from := 0
	for start := finder.next(from); start != startNone; start = finder.next(from) {
		from = start + 1
		if d.word.hasAt(t.units, start-1) {
			continue
		}
		afterLead := start + d.leadLength(t.units, start)
		if afterLead >= len(t.units) || t.units[afterLead] != d.separator {
			continue
		}
		end := d.chainEnd(t.units, &memo, afterLead+1)
		if end == -1 {
			continue
		}
		found = append(found, span{start, end})
		from = end
	}
	return found
}

// leadLength is the length of the first lead (list order) that starts at `start`.
func (d *dashChain) leadLength(units []uint16, start int) int {
	for _, lead := range d.leadUnits {
		if hasUnitsAt(units, lead, start) {
			return len(lead)
		}
	}
	return 0
}

type sendgridSpec struct {
	Lead       string `json:"lead"`
	Separator  string `json:"separator"`
	WordClass  string `json:"wordClass"`
	Dash       string `json:"dash"`
	MaxSegment int    `json:"maxSegment"`
	Length     int    `json:"length"`
}

// sendgridKey is SPEC 4.13: `SG.` and two runs, a key only when the match is exactly `length` units.
type sendgridKey struct {
	letters    *letterTable
	lead       string
	leadLength int
	separator  uint16
	word       *unitSet
	dash       uint16
	maxSegment int
	length     int
}

func (e *engine) newSendgridKey(b *builder, raw json.RawMessage) (scanner, error) {
	var spec sendgridSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &sendgridKey{
		letters:    e.letters,
		lead:       spec.Lead,
		leadLength: len(decodeUTF8(spec.Lead)),
		separator:  decodeUTF8(spec.Separator)[0],
		word:       b.class(spec.WordClass),
		dash:       decodeUTF8(spec.Dash)[0],
		maxSegment: spec.MaxSegment,
		length:     spec.Length,
	}, b.err
}

// tailEnd is the end of the match the expression finds after the second separator at `position`:
// a short run, the dash and a second run, or the one long run; -1 when there is none.
func (s *sendgridKey) tailEnd(units []uint16, memo *runMemo, position int) int {
	end := memo.end(units, s.word, position)
	length := end - position
	if length == 0 {
		return -1
	}
	isShortBeforeDash := length <= s.maxSegment && end < len(units) && units[end] == s.dash
	if isShortBeforeDash {
		after := memo.end(units, s.word, end+1)
		if joined := after - (end + 1); joined >= 1 && joined <= s.maxSegment {
			return after
		}
	}
	if length >= 2 && length <= 2*s.maxSegment {
		return end
	}
	return -1
}

func (s *sendgridKey) matchEnd(units []uint16, memo *runMemo, start int) int {
	afterLead := start + s.leadLength
	firstEnd := memo.end(units, s.word, afterLead)
	firstLength := firstEnd - afterLead
	isFirstValid := firstLength >= 1 && firstLength <= s.maxSegment
	hasSeparator := firstEnd < len(units) && units[firstEnd] == s.separator
	if !isFirstValid || !hasSeparator {
		return -1
	}
	return s.tailEnd(units, memo, firstEnd+1)
}

func (s *sendgridKey) scan(t *text) []span {
	var memo runMemo
	finder := newStarts(t, []string{s.lead})
	var found []span
	from := 0
	for start := finder.next(from); start != startNone; start = finder.next(from) {
		from = start + 1
		if !s.letters.passesGuard(t.units, start) {
			continue
		}
		end := s.matchEnd(t.units, &memo, start)
		if end == -1 {
			continue
		}
		from = end
		if end-start == s.length {
			found = append(found, span{start, end})
		}
	}
	return found
}
