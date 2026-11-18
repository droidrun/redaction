package redaction

import (
	"errors"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// text is the input of every rule: UTF-16 code units (the normative unit of the spec) and the
// same text as UTF-8 for the regexp engine, where each unit is one character. A unit in D800 to
// DFFF is written as a private-use character that no pattern mentions (spec section 1), so
// every match offset maps back to a unit offset one to one.
type text struct {
	units  []uint16
	mapped string
	// folded is mapped with ASCII letters lower-cased, made when a search first needs it.
	folded string
	// offs maps a unit index to its byte offset in mapped (length units+1). It is nil when mapped
	// is ASCII, where a unit is one byte.
	offs []int32
}

const (
	surrogateStart = 0xD800
	surrogateEnd   = 0xDFFF
	mappedBase     = 0xF0000
)

var errTextTooLarge = errors.New("redaction: text too large")

func isSurrogate(unit uint16) bool {
	return unit >= surrogateStart && unit <= surrogateEnd
}

func isHighSurrogate(unit uint16) bool {
	return unit >= 0xD800 && unit <= 0xDBFF
}

func isLowSurrogate(unit uint16) bool {
	return unit >= 0xDC00 && unit <= 0xDFFF
}

// decodeUTF8 turns a Go string into code units. A byte sequence that is not valid UTF-8 becomes
// one U+FFFD per invalid byte; it is never skipped.
func decodeUTF8(s string) []uint16 {
	units := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		units = appendRune(units, r)
	}
	return units
}

func appendRune(units []uint16, r rune) []uint16 {
	if r < 0x10000 {
		return append(units, uint16(r))
	}
	r -= 0x10000
	return append(units, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
}

func isASCIIUnits(units []uint16) bool {
	for _, unit := range units {
		if unit >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func mappedRune(unit uint16) rune {
	if isSurrogate(unit) {
		return mappedBase + rune(unit-surrogateStart)
	}
	return rune(unit)
}

func newText(units []uint16) *text {
	if isASCIIUnits(units) {
		raw := make([]byte, len(units))
		for i, unit := range units {
			raw[i] = byte(unit)
		}
		return &text{units: units, mapped: string(raw)}
	}
	var builder strings.Builder
	builder.Grow(len(units) * 3)
	offs := make([]int32, len(units)+1)
	for i, unit := range units {
		if builder.Len() > math.MaxInt32-utf8.UTFMax {
			panic(errTextTooLarge)
		}
		offs[i] = int32(builder.Len())
		builder.WriteRune(mappedRune(unit))
	}
	offs[len(units)] = int32(builder.Len())
	return &text{units: units, mapped: builder.String(), offs: offs}
}

func textFromString(s string) *text {
	return newText(decodeUTF8(s))
}

func (t *text) foldedText() string {
	if t.folded == "" {
		t.folded = lowerASCII(t.mapped)
	}
	return t.folded
}

func (t *text) length() int {
	return len(t.units)
}

func (t *text) byteAt(unit int) int {
	if t.offs == nil {
		return unit
	}
	return int(t.offs[unit])
}

func (t *text) unitAt(byteOffset int) int {
	if t.offs == nil {
		return byteOffset
	}
	return sort.Search(len(t.offs), func(i int) bool { return int(t.offs[i]) >= byteOffset })
}

func isWordByte(b byte) bool {
	isDigit := b >= '0' && b <= '9'
	isLetter := (b|0x20) >= 'a' && (b|0x20) <= 'z'
	return isDigit || isLetter || b == '_'
}

// searcher runs one expanded spec pattern from any unit offset with the full text as left
// context. Go has no search-from-offset, and a slice would turn the character before the offset
// into "start of text" for \b. A slice is exact when that character is not a word character; if
// it is, the pattern is run with one arbitrary character in front, taken from the text itself.
type searcher struct {
	source string
	plain  *regexp.Regexp
	ctx    *regexp.Regexp
	// needs are literals of which every match holds one (lower-cased); empty when there are none.
	needs []string
}

func newSearcher(source string) (*searcher, error) {
	plain, err := regexp.Compile(source)
	if err != nil {
		return nil, errors.New("redaction: spec pattern does not compile")
	}
	ctx, err := regexp.Compile(`(?s:.)(?:` + source + `)`)
	if err != nil {
		return nil, errors.New("redaction: spec pattern does not compile")
	}
	needs, err := requiredLiterals(source)
	if err != nil {
		return nil, errors.New("redaction: spec pattern does not parse")
	}
	return &searcher{source: source, plain: plain, ctx: ctx, needs: needs}, nil
}

// find returns the leftmost-first match that starts at or after unit `from`, as unit offsets
// (start and end of the match, then of each capture group; -1 for a group that did not take part).
func (s *searcher) find(t *text, from int) []int {
	if from >= t.length() {
		return nil
	}
	if from == 0 && !holdsAny(t.foldedText(), s.needs) {
		return nil
	}
	start := t.byteAt(from)
	base := start
	var loc []int
	if from == 0 || !isWordByte(t.mapped[start-1]) {
		loc = s.plain.FindStringSubmatchIndex(t.mapped[start:])
	} else {
		base = t.byteAt(from - 1)
		loc = s.ctx.FindStringSubmatchIndex(t.mapped[base:])
		if loc != nil {
			_, width := utf8.DecodeRuneInString(t.mapped[base+loc[0]:])
			loc[0] += width
		}
	}
	if loc == nil {
		return nil
	}
	for i, offset := range loc {
		if offset >= 0 {
			loc[i] = t.unitAt(base + offset)
		}
	}
	return loc
}

// anchored matches a pattern exactly at a unit offset. The pattern must not hold \b: the slice
// it runs on hides the character before the offset.
type anchored struct {
	re *regexp.Regexp
}

func newAnchored(source string, suffix string) (*anchored, error) {
	if strings.Contains(source, `\b`) {
		return nil, errors.New("redaction: anchored spec pattern uses a word boundary")
	}
	re, err := regexp.Compile(`^(?:` + source + `)` + suffix)
	if err != nil {
		return nil, errors.New("redaction: spec pattern does not compile")
	}
	return &anchored{re: re}, nil
}

// end returns the end unit of the match that starts exactly at unit `at`, or -1.
func (a *anchored) end(t *text, at int) int {
	if at < 0 || at > t.length() {
		return -1
	}
	start := t.byteAt(at)
	loc := a.re.FindStringIndex(t.mapped[start:])
	if loc == nil {
		return -1
	}
	return t.unitAt(start + loc[1])
}

// indexFrom is the unit index of the first occurrence of `literal` at or after unit `from`, or -1.
// A literal holds no surrogate (a unit of D800 to DFFF is not in the mapped text as itself), so a
// match in the mapped text is a match in the units.
func (t *text) indexFrom(literal string, from int) int {
	if from >= t.length() {
		return -1
	}
	start := t.byteAt(from)
	at := strings.Index(t.mapped[start:], literal)
	if at < 0 {
		return -1
	}
	return t.unitAt(start + at)
}
