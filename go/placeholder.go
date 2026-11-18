package redaction

import (
	"errors"
	"regexp"
	"strings"
)

// placeholders knows the placeholder grammar of the spec (SPEC section 7).
type placeholders struct {
	prefix *anchored
	whole  *anchored
	all    *regexp.Regexp
	open   string
	close  string
	strip  []string
}

func newPlaceholders(spec *loadedSpec, grammar string) (*placeholders, error) {
	prefix, err := newAnchored(grammar, "")
	if err != nil {
		return nil, err
	}
	whole, err := newAnchored(grammar, `\z`)
	if err != nil {
		return nil, err
	}
	all, err := regexp.Compile(grammar)
	if err != nil {
		return nil, errors.New("redaction: spec pattern does not compile")
	}
	format := spec.algorithms.Placeholder
	return &placeholders{
		prefix: prefix,
		whole:  whole,
		all:    all,
		open:   format.Open,
		close:  format.Close,
		strip:  format.StripPrefixes,
	}, nil
}

// shorten removes each leading prefix of the spec's list once, in order.
func (p *placeholders) shorten(ruleID string) string {
	id := ruleID
	for _, prefix := range p.strip {
		id = strings.TrimPrefix(id, prefix)
	}
	return id
}

// read is the read form `[REDACTED:<id>]`.
func (p *placeholders) read(ruleID string) string {
	return p.open + p.shorten(ruleID) + p.close
}

func (p *placeholders) readUnits(ruleID string) []uint16 {
	return asUnits(p.read(ruleID))
}

// endAt is the end of the placeholder that starts exactly at `at`, or -1.
func (p *placeholders) endAt(t *text, at int) int {
	return p.prefix.end(t, at)
}

// isValue is true when a placeholder starts at `start` and reaches at least `end` (SPEC 4).
func (p *placeholders) isValue(t *text, start int, end int) bool {
	placeholderEnd := p.endAt(t, start)
	return placeholderEnd != -1 && placeholderEnd >= end
}

// isWhole is true when the units are exactly one placeholder (the end anchor is the text end).
func (p *placeholders) isWhole(units []uint16) bool {
	return p.whole.end(newText(units), 0) >= 0
}

// literalSegments is the text split by every placeholder; empty segments are kept.
func (p *placeholders) literalSegments(t *text) [][]uint16 {
	var segments [][]uint16
	cursor := 0
	for _, loc := range p.all.FindAllStringIndex(t.mapped, -1) {
		segments = append(segments, t.units[cursor:t.unitAt(loc[0])])
		cursor = t.unitAt(loc[1])
	}
	return append(segments, t.units[cursor:])
}
