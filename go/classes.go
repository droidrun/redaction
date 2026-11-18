package redaction

import "errors"

// unitSet is a set of UTF-16 code units: a spec character class compiled to a bit table.
type unitSet [1024]uint64

func (s *unitSet) has(unit uint16) bool {
	return s[unit>>6]&(1<<(unit&63)) != 0
}

func (s *unitSet) add(low, high rune) {
	for r := low; r <= high; r++ {
		s[r>>6] |= 1 << (r & 63)
	}
}

func (s *unitSet) invert() {
	for i := range s {
		s[i] = ^s[i]
	}
}

// negated is a copy that holds exactly the units this set does not.
func (s *unitSet) negated() *unitSet {
	flipped := *s
	flipped.invert()
	return &flipped
}

// hasAt is true when the unit at `at` exists and is in the set.
func (s *unitSet) hasAt(units []uint16, at int) bool {
	return at >= 0 && at < len(units) && s.has(units[at])
}

func rangeSet(low rune, high rune) *unitSet {
	set := &unitSet{}
	set.add(low, high)
	return set
}

func (s *unitSet) hasAnyIn(units []uint16) bool {
	for _, unit := range units {
		if s.has(unit) {
			return true
		}
	}
	return false
}

var errBadClass = errors.New("redaction: spec class is not a portable class")

// classReader reads the members of one expanded class `[...]` or `[^...]`.
type classReader struct {
	runes []rune
	at    int
}

func (c *classReader) more() bool {
	return c.at < len(c.runes)
}

func (c *classReader) member() (rune, error) {
	if !c.more() {
		return 0, errBadClass
	}
	r := c.runes[c.at]
	c.at++
	if r != '\\' {
		return r, nil
	}
	if !c.more() {
		return 0, errBadClass
	}
	escaped := c.runes[c.at]
	c.at++
	return escaped, nil
}

func (c *classReader) isRange() bool {
	return c.at+1 < len(c.runes) && c.runes[c.at] == '-'
}

// parseClass compiles an expanded spec class (explicit characters and ranges, no escapes but a
// backslash before punctuation) into a unit table. A negated class includes every surrogate unit.
func parseClass(expanded string) (*unitSet, error) {
	reader := &classReader{runes: []rune(expanded)}
	if len(reader.runes) < 3 || reader.runes[0] != '[' || reader.runes[len(reader.runes)-1] != ']' {
		return nil, errBadClass
	}
	reader.runes = reader.runes[:len(reader.runes)-1]
	reader.at = 1
	negated := reader.runes[1] == '^'
	if negated {
		reader.at = 2
	}
	set := &unitSet{}
	for reader.more() {
		low, err := reader.member()
		if err != nil {
			return nil, err
		}
		high := low
		if reader.isRange() {
			reader.at++
			high, err = reader.member()
			if err != nil {
				return nil, err
			}
		}
		if low > high || high > 0xFFFF {
			return nil, errBadClass
		}
		set.add(low, high)
	}
	if negated {
		set.invert()
	}
	return set, nil
}
