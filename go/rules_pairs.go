package redaction

import "encoding/json"

// pairValues are the drops of SPEC 4.7 step 4: empty, placeholder, trivial or stand-in values.
func (e *engine) realPairValues(t *text, ranges []span) []span {
	var kept []span
	for _, found := range ranges {
		if found.end <= found.start || e.placeholders.isValue(t, found.start, found.end) {
			continue
		}
		value := t.units[found.start:found.end]
		if !e.evidence.isTrivialValue(value) && !e.evidence.isDocPlaceholder(value) {
			kept = append(kept, found)
		}
	}
	return kept
}

type keywordSpec struct {
	Prefix         string `json:"prefix"`
	PlainChar      string `json:"plainChar"`
	EscapeStop     string `json:"escapeStop"`
	MinValueLength int    `json:"minValueLength"`
	Window         int    `json:"window"`
	IdentChar      string `json:"identChar"`
	LabelLookback  int    `json:"labelLookback"`
}

// keywordPairs is SPEC 4.6: a credential keyword in an identifier, a separator and a value that
// shows evidence of being secret.
type keywordPairs struct {
	search   *searcher
	run      runClasses
	minValue int
	window   int
	ident    *unitSet
	lookback int
	evidence *evidence
	holders  *placeholders
}

func (e *engine) newKeywordPairs(b *builder, raw json.RawMessage) (scanner, error) {
	var spec keywordSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &keywordPairs{
		search:   b.searcher(spec.Prefix),
		run:      runClasses{plain: b.class(spec.PlainChar), stop: b.class(spec.EscapeStop)},
		minValue: spec.MinValueLength,
		window:   spec.Window,
		ident:    b.class(spec.IdentChar),
		lookback: spec.LabelLookback,
		evidence: e.evidence,
		holders:  e.placeholders,
	}, b.err
}

func (k *keywordPairs) accepts(t *text, value span) bool {
	if value.end <= value.start || k.holders.isValue(t, value.start, value.end) {
		return false
	}
	return k.evidence.hasValueEvidence(t.units[value.start:value.end])
}

func (k *keywordPairs) scan(t *text) []span {
	var found []span
	for from := 0; ; {
		loc := k.search.find(t, from)
		if loc == nil {
			return found
		}
		matchStart, valueStart := loc[0], loc[1]
		valueEnd := guardedRunEnd(t.units, valueStart, k.run, k.window)
		if valueEnd-valueStart < k.minValue {
			from = matchStart + 1
			continue
		}
		label := labelStart(t.units, matchStart, k.ident, k.lookback)
		value := trimQueryValue(t.units, label, span{valueStart, valueEnd})
		if !k.accepts(t, value) {
			from = valueStart
			continue
		}
		end := value.end
		if value.end-value.start == k.window {
			end = guardedRunEnd(t.units, value.end, k.run, unbounded)
		}
		found = append(found, span{value.start, end})
		from = max(end, valueStart)
	}
}

type quotedSpec struct {
	Label      string `json:"label"`
	ValueLimit int    `json:"valueLimit"`
}

// quotedPairs is SPEC 4.7: a quoted value, with escaped quotes and JSON-in-JSON layers.
type quotedPairs struct {
	e          *engine
	search     *searcher
	valueLimit int
}

func (e *engine) newQuotedPairs(b *builder, raw json.RawMessage) (scanner, error) {
	var spec quotedSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &quotedPairs{e: e, search: b.searcher(spec.Label), valueLimit: spec.ValueLimit}, b.err
}

func backslashesBefore(units []uint16, at int, floor int) int {
	run := 0
	for at-run-1 >= floor && units[at-run-1] == backslash {
		run++
	}
	return run
}

func closesValue(layers int, run int) bool {
	if layers == 0 {
		return run%2 == 0
	}
	return run == layers
}

// closingQuote is the end of a value that opened at `from`, or -1 when no quote closes it.
func closingQuote(units []uint16, from int, quote uint16, layers int, limit int) int {
	for i := from; i < limit; i++ {
		if units[i] != quote {
			continue
		}
		run := backslashesBefore(units, i, from)
		if closesValue(layers, run) {
			return i - run
		}
	}
	return -1
}

func (q *quotedPairs) scan(t *text) []span {
	var found []span
	for from := 0; ; {
		loc := q.search.find(t, from)
		if loc == nil {
			break
		}
		valueStart := loc[1]
		layers := loc[3] - loc[2]
		quote := t.units[loc[4]]
		limit := min(t.length(), valueStart+q.valueLimit)
		closeAt := closingQuote(t.units, valueStart, quote, layers, limit)
		if closeAt < 0 {
			found = append(found, span{valueStart, t.length()})
			break
		}
		found = append(found, span{valueStart, closeAt})
		from = closeAt
	}
	return q.e.realPairValues(t, found)
}

type unquotedSpec struct {
	Prefix     string `json:"prefix"`
	PlainChar  string `json:"plainChar"`
	EscapeStop string `json:"escapeStop"`
}

// unquotedPairs is SPEC 4.8: the value ends at whitespace or a delimiter.
type unquotedPairs struct {
	e      *engine
	search *searcher
	run    runClasses
}

func (e *engine) newUnquotedPairs(b *builder, raw json.RawMessage) (scanner, error) {
	var spec unquotedSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &unquotedPairs{
		e:      e,
		search: b.searcher(spec.Prefix),
		run:    runClasses{plain: b.class(spec.PlainChar), stop: b.class(spec.EscapeStop)},
	}, b.err
}

func (u *unquotedPairs) scan(t *text) []span {
	var found []span
	for from := 0; ; {
		loc := u.search.find(t, from)
		if loc == nil {
			break
		}
		end := guardedRunEnd(t.units, loc[1], u.run, unbounded)
		if end == loc[1] {
			from = loc[0] + 1
			continue
		}
		from = end
		found = append(found, trimQueryValue(t.units, loc[0], span{loc[1], end}))
	}
	return u.e.realPairValues(t, found)
}
