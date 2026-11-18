package redaction

import "encoding/json"

type authSpec struct {
	Bearer         string   `json:"bearer"`
	Scheme         string   `json:"scheme"`
	ValueClass     string   `json:"valueClass"`
	MinValueLength int      `json:"minValueLength"`
	LowerClass     string   `json:"lowerClass"`
	UpperClass     string   `json:"upperClass"`
	WordClass      string   `json:"wordClass"`
	PlainWords     []string `json:"plainWords"`
}

// authValues is SPEC 4.5: `Bearer <value>`, and `Basic`/`Token <value>` when the value looks
// like a credential and not like a word.
type authValues struct {
	bearer       *searcher
	scheme       *searcher
	value        *unitSet
	minValue     int
	lower        *unitSet
	upper        *unitSet
	word         *unitSet
	plainWords   map[string]bool
	placeholders *placeholders
}

func (e *engine) newAuthValues(b *builder, raw json.RawMessage) (scanner, error) {
	var spec authSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &authValues{
		bearer:       b.searcher(spec.Bearer),
		scheme:       b.searcher(spec.Scheme),
		value:        b.class(spec.ValueClass),
		minValue:     spec.MinValueLength,
		lower:        b.class(spec.LowerClass),
		upper:        b.class(spec.UpperClass),
		word:         b.class(spec.WordClass),
		plainWords:   toSet(spec.PlainWords),
		placeholders: e.placeholders,
	}, b.err
}

func (a *authValues) bearerRanges(t *text) []span {
	var found []span
	for from := 0; ; {
		loc := a.bearer.find(t, from)
		if loc == nil {
			return found
		}
		from = max(loc[1], loc[0]+1)
		if loc[2] >= 0 {
			found = append(found, span{loc[2], loc[3]})
		}
	}
}

func (a *authValues) endsWord(units []uint16, at int) bool {
	return at >= len(units) || !a.word.has(units[at])
}

// isWordShape is true for a plain lower-case word or a Capitalized word that fills the value
// run up to a non-word unit ("Token expired", "Basic information").
func (a *authValues) isWordShape(units []uint16, start int) bool {
	lowerEnd := runEnd(units, start, a.lower, unbounded)
	if lowerEnd > start && a.endsWord(units, lowerEnd) {
		return true
	}
	if start >= len(units) || !a.upper.has(units[start]) {
		return false
	}
	capitalizedEnd := runEnd(units, start+1, a.lower, unbounded)
	return capitalizedEnd > start+1 && a.endsWord(units, capitalizedEnd)
}

func (a *authValues) schemeRanges(t *text) []span {
	var found []span
	for from := 0; ; {
		loc := a.scheme.find(t, from)
		if loc == nil {
			return found
		}
		start := loc[1]
		end := runEnd(t.units, start, a.value, unbounded)
		if end-start < a.minValue || a.isWordShape(t.units, start) {
			from = loc[0] + 1
			continue
		}
		found = append(found, span{start, end})
		from = end
	}
}

func (a *authValues) scan(t *text) []span {
	var kept []span
	for _, found := range append(a.bearerRanges(t), a.schemeRanges(t)...) {
		word := foldString(t.units[found.start:found.end])
		if !a.plainWords[word] && !a.placeholders.isValue(t, found.start, found.end) {
			kept = append(kept, found)
		}
	}
	return kept
}
