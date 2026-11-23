package redaction

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// placeholders knows the placeholder grammar of the spec (SPEC section 7).
type placeholders struct {
	prefix *anchored
	whole  *anchored
	all    *regexp.Regexp
	open   string
	// marker is open without its rule separator: the text a key holds when it holds a placeholder.
	marker []uint16
	close  string
	// numberMark is the text before the number of a numbered key (`#` in `[REDACTED:npm#2]`).
	numberMark string
	strip      []string
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
	if format.NumberMark == "" {
		return nil, errSpecRejected
	}
	return &placeholders{
		prefix:     prefix,
		whole:      whole,
		all:        all,
		open:       format.Open,
		marker:     decodeUTF8(strings.TrimSuffix(format.Open, ":")),
		close:      format.Close,
		numberMark: format.NumberMark,
		strip:      format.StripPrefixes,
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
	return decodeUTF8(p.read(ruleID))
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

// numberAt is where the number goes in a changed key (SPEC 8, key collisions): just before the `]` of its
// last placeholder, when that is exactly `[REDACTED:<rule>]` with a rule that has no `:suffix` and does not
// itself end with the number mark and digits (`[REDACTED:npm#2]`). A key without a placeholder, with the bare
// `[REDACTED]`, with a suffix, or with a numbered last placeholder has no place for a number.
func (p *placeholders) numberAt(key []uint16) (int, bool) {
	t := newText(key)
	found := p.all.FindAllStringIndex(t.mapped, -1)
	if len(found) == 0 {
		return 0, false
	}
	start, end := t.unitAt(found[len(found)-1][0]), t.unitAt(found[len(found)-1][1])
	if !hasUnitsAt(key, decodeUTF8(p.open), start) {
		return 0, false // the bare `[REDACTED]`
	}
	rule := unitsToString(key[start+len(p.open) : end-len(p.close)])
	if strings.Contains(rule, ":") || p.endsWithNumber(rule) {
		return 0, false
	}
	return end - len(p.close), true
}

// endsWithNumber: the rule ends with the number mark and one or more digits.
func (p *placeholders) endsWithNumber(rule string) bool {
	at := strings.LastIndex(rule, p.numberMark)
	if at < 0 || at == len(rule)-len(p.numberMark) {
		return false
	}
	for _, digit := range rule[at+len(p.numberMark):] {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// numbered is the key with the number mark and `n` inserted at `at`.
func (p *placeholders) numbered(key []uint16, at int, n int) []uint16 {
	number := decodeUTF8(p.numberMark + strconv.Itoa(n))
	numbered := make([]uint16, 0, len(key)+len(number))
	numbered = append(numbered, key[:at]...)
	numbered = append(numbered, number...)
	return append(numbered, key[at:]...)
}
