package redaction

import "encoding/json"

type keyPairsSpec struct {
	Label            string   `json:"label"`
	ValueLimit       int      `json:"valueLimit"`
	PlainChar        string   `json:"plainChar"`
	EscapeStop       string   `json:"escapeStop"`
	IdentChar        string   `json:"identChar"`
	LabelLookback    int      `json:"labelLookback"`
	KeyChar          string   `json:"keyChar"`
	KeyMax           int      `json:"keyMax"`
	GapClass         string   `json:"gapClass"`
	QuoteChar        string   `json:"quoteChar"`
	DigitClass       string   `json:"digitClass"`
	StandInMinLength int      `json:"standInMinLength"`
	KeptMaxLength    int      `json:"keptMaxLength"`
	SchemeWords      []string `json:"schemeWords"`
	SchemeKeys       []string `json:"schemeKeys"`
}

// keyPairs is SPEC 4.18: `key: value` pairs decided by the key verdict of SPEC 6, the one that decides
// JSON keys, with the short values and kept values of strict.
type keyPairs struct {
	e          *engine
	search     *searcher
	valueLimit int
	run        runClasses
	ident      *unitSet
	keyChar    *unitSet
	keyMax     int
	lookback   int
	gap        *unitSet
	quote      *unitSet
	digit      *unitSet
	standInMin int
	keptMax    int
	status     map[string]bool
	schemeWord map[string]bool
	schemeKey  map[string]bool
}

func (e *engine) newKeyPairs(b *builder, raw json.RawMessage) (scanner, error) {
	var spec keyPairsSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &keyPairs{
		e:          e,
		search:     b.searcher(spec.Label),
		valueLimit: spec.ValueLimit,
		run:        runClasses{plain: b.class(spec.PlainChar), stop: b.class(spec.EscapeStop)},
		ident:      b.class(spec.IdentChar),
		keyChar:    b.class(spec.KeyChar),
		keyMax:     spec.KeyMax,
		lookback:   spec.LabelLookback,
		gap:        b.class(spec.GapClass),
		quote:      b.class(spec.QuoteChar),
		digit:      b.class(spec.DigitClass),
		standInMin: spec.StandInMinLength,
		keptMax:    spec.KeptMaxLength,
		status:     toSet(b.spec.rules.StatusWords),
		schemeWord: toSet(spec.SchemeWords),
		schemeKey:  toSet(spec.SchemeKeys),
	}, b.err
}

var backslashes = rangeSet(backslash, backslash)

// keyBefore is the key that stands before the separator at `at`: spaces, an optional (escaped) quote, then up
// to `keyMax` units of `keyChar`; ok is false when no key stands there.
func (k *keyPairs) keyBefore(units []uint16, at int) (key span, ok bool) {
	end := labelStart(units, at, k.gap, unbounded)
	if end > 0 && k.quote.has(units[end-1]) {
		end = labelStart(units, end-1, backslashes, unbounded)
	}
	start := labelStart(units, end, k.keyChar, k.keyMax)
	return span{start, end}, start != end
}

// isAuthorizationKey is true when the key, lower-cased without `-` and `_`, is a scheme key.
func (k *keyPairs) isAuthorizationKey(key []uint16) bool {
	var compact []uint16
	for _, unit := range lowerUnits(key) {
		if unit != '-' && unit != '_' {
			compact = append(compact, unit)
		}
	}
	return k.schemeKey[foldString(compact)]
}

func (k *keyPairs) isDigits(value []uint16) bool {
	return runEnd(value, 0, k.digit, unbounded) == len(value)
}

// isKept is true for a value that stays under a key whose verdict says secret: a stand-in, a documentation
// placeholder, a status word, an authorization scheme word under an authorization key, and under a `string`
// verdict a plain number. The caller has checked that the value is not longer than `keptMaxLength`.
func (k *keyPairs) isKept(key []uint16, value []uint16, verdict Verdict) bool {
	isStandIn := len(value) >= k.standInMin && k.e.evidence.isTrivialValue(value)
	if isStandIn || k.e.evidence.isDocPlaceholder(value) {
		return true
	}
	word := foldString(k.e.evidence.trim(value))
	if k.status[word] || (k.schemeWord[word] && k.isAuthorizationKey(key)) {
		return true
	}
	return verdict == VerdictString && k.isDigits(value)
}

// queryValueEnd is `trimQueryValue` (SPEC 5.3) with the next `&` remembered: a text of many pairs inside one
// long run would otherwise read the run at every pair.
func queryValueEnd(units []uint16, ampersands *starts, label int, value span) int {
	if label == 0 || (units[label-1] != '?' && units[label-1] != '&') {
		return value.end
	}
	next := ampersands.next(value.start)
	if next == -1 || next >= value.end {
		return value.end
	}
	return next
}

// isRedacted is true for a value that is not empty, not a placeholder and not kept (SPEC 4.18 step 3).
func (k *keyPairs) isRedacted(t *text, key span, value span, verdict Verdict) bool {
	if value.end <= value.start || k.e.placeholders.isValue(t, value.start, value.end) {
		return false
	}
	isShort := value.end-value.start <= k.keptMax
	return !isShort || !k.isKept(t.units[key.start:key.end], t.units[value.start:value.end], verdict)
}

func (k *keyPairs) scan(t *text) []span {
	var found []span
	var memo runMemo
	ampersands := newStarts(t, []string{"&"})
	measure := func(from int) int { return guardedRunEnd(t.units, from, k.run, unbounded) }
	for from := 0; ; {
		loc := k.search.find(t, from)
		if loc == nil {
			return found
		}
		matchStart, valueStart := loc[0], loc[1]
		from = valueStart
		key, hasKey := k.keyBefore(t.units, matchStart)
		if !hasKey {
			continue
		}
		verdict := k.e.keys.keyVerdict(t.units[key.start:key.end])
		if verdict == VerdictNone {
			continue
		}
		isQuoted := loc[4] >= 0
		var stop int
		if isQuoted {
			layers := loc[3] - loc[2]
			limit := min(t.length(), valueStart+k.valueLimit)
			stop = closingQuote(t.units, valueStart, t.units[loc[4]], layers, limit)
			if stop < 0 {
				return k.failClosed(t, valueStart, found)
			}
		} else {
			stop = memo.remember(valueStart, measure)
			if stop == valueStart {
				from = matchStart + 1
				continue
			}
			label := labelStart(t.units, key.start, k.ident, k.lookback)
			stop = queryValueEnd(t.units, ampersands, label, span{valueStart, stop})
		}
		if !k.isRedacted(t, key, span{valueStart, stop}, verdict) {
			continue
		}
		found = append(found, span{valueStart, stop})
		if isQuoted {
			from = max(stop, valueStart)
		}
	}
}

// failClosed is the end of the scan at a quoted value with no closing quote: the rest of the text is the
// value, unless it is empty or already a placeholder.
func (k *keyPairs) failClosed(t *text, valueStart int, found []span) []span {
	if valueStart < t.length() && !k.e.placeholders.isValue(t, valueStart, t.length()) {
		found = append(found, span{valueStart, t.length()})
	}
	return found
}
