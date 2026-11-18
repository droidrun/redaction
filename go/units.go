package redaction

// span is a half-open range of unit offsets.
type span struct {
	start int
	end   int
}

// hit is a detected range and the id of the rule that found it.
type hit struct {
	id    string
	start int
	end   int
}

// runEnd is the end of the run of units in `set` that starts at `from`, at most `max` long.
func runEnd(units []uint16, from int, set *unitSet, max int) int {
	end := from
	for end < len(units) && end-from < max && set.has(units[end]) {
		end++
	}
	return end
}

const unbounded = int(^uint(0) >> 1)

// runClasses are the two classes of a guarded run (SPEC 5.1).
type runClasses struct {
	plain *unitSet
	stop  *unitSet
}

const backslash = 0x5C

// guardedRunEnd is the end of a run of plain units, where a backslash joins the run unless it
// begins an escape (the next unit is in the stop class). At most `max` units long.
func guardedRunEnd(units []uint16, from int, classes runClasses, max int) int {
	end := from
	for end < len(units) && end-from < max {
		unit := units[end]
		if !classes.plain.has(unit) && !beginsNoEscape(units, end, classes.stop) {
			break
		}
		end++
	}
	return end
}

func beginsNoEscape(units []uint16, at int, stop *unitSet) bool {
	if units[at] != backslash {
		return false
	}
	return at+1 >= len(units) || !stop.has(units[at+1])
}

// indexUnits is the index of `needle` in `units` at or after `from`, or -1.
func indexUnits(units []uint16, needle []uint16, from int) int {
	for i := from; i+len(needle) <= len(units); i++ {
		if hasUnitsAt(units, needle, i) {
			return i
		}
	}
	return -1
}

func hasUnitsAt(units []uint16, needle []uint16, at int) bool {
	if at < 0 || at+len(needle) > len(units) {
		return false
	}
	for i, unit := range needle {
		if units[at+i] != unit {
			return false
		}
	}
	return true
}

func containsUnits(units []uint16, needle []uint16) bool {
	return indexUnits(units, needle, 0) >= 0
}

func equalUnits(a []uint16, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	return hasUnitsAt(a, b, 0)
}

// labelStart is the start of the identifier that holds the keyword at `keyword` (SPEC 5.2).
func labelStart(units []uint16, keyword int, ident *unitSet, lookback int) int {
	start := keyword
	for start > 0 && keyword-start < lookback && ident.has(units[start-1]) {
		start--
	}
	return start
}

// trimQueryValue cuts a value inside a URL query at the next `&` (SPEC 5.3).
func trimQueryValue(units []uint16, label int, value span) span {
	if label == 0 {
		return value
	}
	before := units[label-1]
	if before != '?' && before != '&' {
		return value
	}
	for i := value.start; i < value.end; i++ {
		if units[i] == '&' {
			return span{value.start, i}
		}
	}
	return value
}
