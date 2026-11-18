package redaction

// Small linear helpers the full-tier scanners share. Both keep state for ONE scan of ONE text, so a
// scanner makes them at the start of each call.

const (
	startUnknown = -2
	startNone    = -1
)

// starts finds the next position where one of a few literals begins. Each literal is searched
// forward only: its last answer is kept and reused while it is not behind `from`, so a scan that
// asks for starts in increasing order costs one pass per literal.
type starts struct {
	t        *text
	literals []string
	known    []int
}

func newStarts(t *text, literals []string) *starts {
	known := make([]int, len(literals))
	for i := range known {
		known[i] = startUnknown
	}
	return &starts{t: t, literals: literals, known: known}
}

// next is the first position at or after `from` where a literal starts, or -1. `from` never goes
// back between calls.
func (s *starts) next(from int) int {
	best := startNone
	for i, literal := range s.literals {
		known := s.known[i]
		isStale := known != startNone && known < from
		if known == startUnknown || isStale {
			known = s.t.indexFrom(literal, from)
			s.known[i] = known
		}
		isEarlier := best == startNone || known < best
		if known != startNone && isEarlier {
			best = known
		}
	}
	return best
}

// runMemo remembers the last run of a class that was measured: the start and the end. A later start
// that lies inside it gets the same end without walking the run again (SPEC 4.11).
type runMemo struct {
	low  int
	high int
}

// end is the end of the maximal run of units of `set` that starts at `from` (`from` itself when
// there is none).
func (m *runMemo) end(units []uint16, set *unitSet, from int) int {
	if from >= m.low && from < m.high {
		return m.high
	}
	end := runEnd(units, from, set, unbounded)
	m.low, m.high = from, end
	return end
}
