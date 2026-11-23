package redaction

import "sort"

// The full tier (SPEC 4.17 and 9.4): the standard rules plus the full-tier rules of the spec, which
// see only the first `scanCap` units of a text, in overlapping windows.

// detectFullRules runs every full-tier rule over one text; the hits are ordered by start, then by
// end (rule order breaks ties).
func (e *engine) detectFullRules(t *text) []hit {
	hits := collectHits(e.full, t)
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		return hits[i].end < hits[j].end
	})
	return hits
}

// detectFullWindows runs the full-tier rules over the first `scanCap` units: in one pass when the
// text fits a window, else window by window (each window is a text of its own, as in the reference:
// the letter guard and `\b` see the start of the window as the start of the text), moved to absolute
// offsets and merged.
func (e *engine) detectFullWindows(t *text) []hit {
	limits := e.spec.algorithms.Full
	scanLen := min(t.length(), limits.ScanCap)
	if scanLen <= limits.ScanWindow {
		return e.detectFullRules(t)
	}
	stride := limits.ScanWindow - limits.ScanOverlap
	var all []hit
	for offset := 0; offset < scanLen; offset += stride {
		windowEnd := min(offset+limits.ScanWindow, scanLen)
		for _, found := range e.detectFullRules(newText(t.units[offset:windowEnd])) {
			all = append(all, hit{id: found.id, start: found.start + offset, end: found.end + offset})
		}
		if windowEnd >= scanLen {
			break
		}
	}
	return mergeHits(all)
}

// detectFull is the full tier's `detect`: the merge of the full-tier hits and the standard hits (the
// full-tier hits come first, so on an equal start their rule id wins).
func (e *engine) detectFull(t *text) []hit {
	if t.length() < e.spec.algorithms.Text.MinScanLength {
		return nil
	}
	return mergeHits(append(e.detectFullWindows(t), e.detect(t)...))
}

// tryDetect runs a detector and reports whether it finished; a panic is a failure.
func (e *engine) tryDetect(detect func() []hit) (hits []hit, finished bool) {
	defer func() {
		if recover() != nil {
			hits, finished = nil, false
		}
	}()
	return detect(), true
}

// errorText records the `error` hit and gives its placeholder.
func (e *engine) errorText(rec *recorder) []uint16 {
	id := e.spec.algorithms.RuleIDs.Error
	rec.add(id)
	return e.placeholders.readUnits(id)
}

// redactFullCompat is the full tier in compat mode (SPEC 9.4): when the full-tier rules fail, the
// standard rules run alone; when those fail too, the whole text is `[REDACTED:error]`.
func (e *engine) redactFullCompat(units []uint16, rec *recorder) []uint16 {
	t := newText(units)
	hits, finished := e.tryDetect(func() []hit { return e.detectFull(t) })
	if !finished {
		hits, finished = e.tryDetect(func() []hit { return e.detect(t) })
	}
	if !finished {
		return e.errorText(rec)
	}
	rec.addHits(hits)
	return e.splice(units, hits)
}

// redactFullStrict is the full tier in strict mode: a failure replaces the whole text (no fallback),
// and the units beyond the scan cap are replaced by `[REDACTED:size-limit]`, merged with any hit they
// touch. Every caller (redactText, the walker's leaf and key) has replaced a text over `maxChars`
// before it gets here.
func (e *engine) redactFullStrict(units []uint16, rec *recorder) []uint16 {
	sizeLimit := e.spec.algorithms.RuleIDs.SizeLimit
	t := newText(units)
	hits, finished := e.tryDetect(func() []hit { return e.detectFull(t) })
	if !finished {
		return e.errorText(rec)
	}
	if scanCap := e.spec.algorithms.Full.ScanCap; len(units) > scanCap {
		hits = mergeHits(append(hits, hit{id: sizeLimit, start: scanCap, end: len(units)}))
		rec.fail(sizeLimit)
	}
	rec.addHits(hits)
	return e.splice(units, hits)
}
