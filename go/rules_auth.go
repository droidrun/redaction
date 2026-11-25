package redaction

import "encoding/json"

type authSpec struct {
	Header         []string `json:"header"`
	Bearer         string   `json:"bearer"`
	BearerAlso     string   `json:"bearerAlso"`
	BearerWide     string   `json:"bearerWide"`
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
	headers      []*searcher
	bearers      []*searcher
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
	bearers := []*searcher{b.searcher(spec.Bearer)}
	for _, pattern := range []string{spec.BearerAlso, spec.BearerWide} {
		if pattern != "" {
			bearers = append(bearers, b.searcher(pattern))
		}
	}
	var headers []*searcher
	for _, pattern := range spec.Header {
		headers = append(headers, b.searcher(pattern))
	}
	return &authValues{
		headers:      headers,
		bearers:      bearers,
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

// credentialRanges are the credentials of one `bearer` pattern: capture group 1 of every match.
func credentialRanges(search *searcher, t *text) []span {
	var found []span
	for from := 0; ; {
		loc := search.find(t, from)
		if loc == nil {
			return found
		}
		from = max(loc[1], loc[0]+1)
		if loc[2] >= 0 {
			found = append(found, span{loc[2], loc[3]})
		}
	}
}

// Each Bearer pattern searches independently, so a wider match cannot suppress narrower hits.
func (a *authValues) bearerRanges(t *text) []span {
	var found []span
	for _, search := range a.bearers {
		found = append(found, credentialRanges(search, t)...)
	}
	return found
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
	for _, header := range a.headers {
		for from := 0; ; {
			m := header.find(t, from)
			if m == nil {
				break
			}
			from = m[1]
			if foldString(t.units[m[4]:m[5]]) != "bearer" && !a.placeholders.isValue(t, m[6], m[7]) {
				kept = append(kept, span{m[2], m[3]})
			}
		}
	}
	return kept
}
