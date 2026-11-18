package redaction

import "encoding/json"

type querySpec struct {
	QueryKey        string   `json:"queryKey"`
	QueryOnlyKeys   []string `json:"queryOnlyKeys"`
	ValueEnd        string   `json:"valueEnd"`
	NestedEnd       string   `json:"nestedEnd"`
	NestedLimit     int      `json:"nestedLimit"`
	DecodeBudget    int      `json:"decodeBudget"`
	DropPlaceholder bool     `json:"dropPlaceholder"`
}

// queryValues is SPEC 4.9: the values of secret-named URL query parameters, also when they hide
// inside a percent-encoded value of another parameter.
type queryValues struct {
	e            *engine
	search       *searcher
	queryOnly    map[string]bool
	valueEnd     *unitSet
	nestedEnd    *unitSet
	nestedLimit  int
	decodeBudget int
	drop         bool
}

func (e *engine) newQueryValues(b *builder, raw json.RawMessage) (scanner, error) {
	var spec querySpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &queryValues{
		e:            e,
		search:       b.searcher(spec.QueryKey, true),
		queryOnly:    toSet(spec.QueryOnlyKeys),
		valueEnd:     b.class(spec.ValueEnd),
		nestedEnd:    b.class(spec.NestedEnd),
		nestedLimit:  spec.NestedLimit,
		decodeBudget: spec.DecodeBudget,
		drop:         spec.DropPlaceholder,
	}, b.err
}

func (q *queryValues) isSecretParam(key []uint16) bool {
	return q.e.keys.isSecretKeyName(key) || q.queryOnly[foldString(key)]
}

// paramKey is the percent-decoded parameter name of a queryKey match.
func paramKey(t *text, loc []int) []uint16 {
	return percentDecode(t.units[loc[2]:loc[3]])
}

// hasSecretParam is true when `?decoded` holds a secret-named parameter.
func (q *queryValues) hasSecretParam(decoded []uint16) bool {
	t := newText(append([]uint16{'?'}, decoded...))
	for from := 0; ; {
		loc := q.search.find(t, from)
		if loc == nil {
			return false
		}
		if q.isSecretParam(paramKey(t, loc)) {
			return true
		}
		from = max(loc[1], loc[0]+1)
	}
}

// hidesSecretParam is true when a nested value decodes to a query that holds a secret parameter.
func (q *queryValues) hidesSecretParam(raw []uint16) bool {
	if !containsUnits(raw, []uint16{'%'}) {
		return false
	}
	decoded := percentDecode(raw)
	return !equalUnits(decoded, raw) && q.hasSecretParam(decoded)
}

func (q *queryValues) scan(t *text) []span {
	var found []span
	budget := q.decodeBudget
	for from := 0; ; {
		loc := q.search.find(t, from)
		if loc == nil {
			break
		}
		valueStart := loc[1]
		from = valueStart
		if q.isSecretParam(paramKey(t, loc)) {
			end := runEndNot(t.units, valueStart, q.valueEnd, unbounded)
			if end > valueStart {
				found = append(found, span{valueStart, end})
			}
			from = max(valueStart, end)
			continue
		}
		if budget <= 0 {
			continue
		}
		end := runEndNot(t.units, valueStart, q.nestedEnd, q.nestedLimit)
		budget -= end - valueStart
		if q.hidesSecretParam(t.units[valueStart:end]) {
			found = append(found, span{valueStart, end})
		}
	}
	return q.dropped(t, found)
}

func (q *queryValues) dropped(t *text, ranges []span) []span {
	if !q.drop {
		return ranges
	}
	var kept []span
	for _, found := range ranges {
		if found.end > found.start && !q.e.placeholders.isValue(t, found.start, found.end) {
			kept = append(kept, found)
		}
	}
	return kept
}

// runEndNot is the end of the run of units that are not in `stop`, at most `max` long.
func runEndNot(units []uint16, from int, stop *unitSet, max int) int {
	end := from
	for end < len(units) && end-from < max && !stop.has(units[end]) {
		end++
	}
	return end
}
