package redaction

import "math/bits"

func hexDigit(unit uint16) (byte, bool) {
	switch {
	case unit >= '0' && unit <= '9':
		return byte(unit - '0'), true
	case unit >= 'a' && unit <= 'f':
		return byte(unit-'a') + 10, true
	case unit >= 'A' && unit <= 'F':
		return byte(unit-'A') + 10, true
	}
	return 0, false
}

// percentByte reads `%XX` at `at` as a byte.
func percentByte(units []uint16, at int) (byte, bool) {
	if at+2 >= len(units) || units[at] != '%' {
		return 0, false
	}
	high, okHigh := hexDigit(units[at+1])
	low, okLow := hexDigit(units[at+2])
	return high<<4 | low, okHigh && okLow
}

// minByCount is the smallest code point of a UTF-8 sequence of 2, 3 or 4 bytes (overlong check).
var minByCount = [5]uint32{0, 0, 0x80, 0x800, 0x10000}

// decodeSequence reads the UTF-8 sequence whose first byte `first` (at least 0x80) was read just
// before `at`. It returns the code point and the position after the sequence.
func decodeSequence(units []uint16, at int, first byte) (uint32, int, bool) {
	count := bits.LeadingZeros8(^first)
	if count == 1 || count > 4 {
		return 0, at, false
	}
	point := uint32(first) & (0x7F >> count)
	for i := 1; i < count; i++ {
		next, ok := percentByte(units, at)
		if !ok || next&0xC0 != 0x80 {
			return 0, at, false
		}
		point = point<<6 | uint32(next&0x3F)
		at += 3
	}
	isSurrogatePoint := point >= highSurrogateStart && point <= lowSurrogateEnd
	if point < minByCount[count] || isSurrogatePoint || point > 0x10FFFF {
		return 0, at, false
	}
	return point, at, true
}

// percentDecode is decodeURIComponent that never fails: a malformed sequence returns the input
// itself, whole (SPEC 4.9). `+` is not a space.
func percentDecode(units []uint16) []uint16 {
	out := make([]uint16, 0, len(units))
	for at := 0; at < len(units); {
		if units[at] != '%' {
			out = append(out, units[at])
			at++
			continue
		}
		first, ok := percentByte(units, at)
		if !ok {
			return units
		}
		at += 3
		if first < 0x80 {
			out = append(out, uint16(first))
			continue
		}
		point, next, ok := decodeSequence(units, at, first)
		if !ok {
			return units
		}
		out = appendRune(out, rune(point))
		at = next
	}
	return out
}
