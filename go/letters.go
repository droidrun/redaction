package redaction

import (
	"errors"
	"strconv"
	"strings"
)

// letterTable is the set of letters of the letter guard (SPEC 5.6): the Unicode 15.0.0 general
// categories Lu, Ll, Lt, Lm and Lo as sorted, merged ranges, read from algorithms.json. The
// runtime's own tables are not used: their Unicode version differs.
type letterTable struct {
	lows  []uint32
	highs []uint32
}

var errBadLetters = errors.New("redaction: the letter table of the spec is malformed")

const (
	hexBase      = 16
	maxCodePoint = 0x10FFFF
)

// parseLetters reads `lo-hi,lo,lo-hi,...` (hex; a single code point has no dash). The ranges must
// be sorted and must not touch or overlap.
func parseLetters(encoded string) (*letterTable, error) {
	items := strings.Split(encoded, ",")
	table := &letterTable{lows: make([]uint32, len(items)), highs: make([]uint32, len(items))}
	for i, item := range items {
		low, high, _ := strings.Cut(item, "-")
		if high == "" {
			high = low
		}
		first, errFirst := strconv.ParseUint(low, hexBase, 32)
		last, errLast := strconv.ParseUint(high, hexBase, 32)
		isMalformed := errFirst != nil || errLast != nil
		isOutOfOrder := first > last || last > maxCodePoint
		if isMalformed || isOutOfOrder {
			return nil, errBadLetters
		}
		if i > 0 && uint32(first) <= table.highs[i-1]+1 {
			return nil, errBadLetters
		}
		table.lows[i], table.highs[i] = uint32(first), uint32(last)
	}
	return table, nil
}

// isLetter is a binary search over the ranges.
func (t *letterTable) isLetter(codePoint uint32) bool {
	low, high := 0, len(t.lows)-1
	for low <= high {
		middle := (low + high) / 2
		switch {
		case codePoint < t.lows[middle]:
			high = middle - 1
		case codePoint > t.highs[middle]:
			low = middle + 1
		default:
			return true
		}
	}
	return false
}

// codePointBefore is the code point that ends at `at`: a surrogate pair is one code point, a lone
// surrogate is itself.
func codePointBefore(units []uint16, at int) uint32 {
	unit := units[at-1]
	isPair := isLowSurrogate(unit) && at >= 2 && isHighSurrogate(units[at-2])
	if !isPair {
		return uint32(unit)
	}
	return uint32(pairPoint(units[at-2], unit))
}

// passesGuard is the lookbehind `(?<!\p{L})`: true at the start of the text, or when the code point
// before `at` is not a letter.
func (t *letterTable) passesGuard(units []uint16, at int) bool {
	return at == 0 || !t.isLetter(codePointBefore(units, at))
}
