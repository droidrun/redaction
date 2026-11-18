package redaction

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

func appendUnicodeEscape(out []byte, unit uint16) []byte {
	return append(out, '\\', 'u',
		hexDigits[unit>>12&0xF], hexDigits[unit>>8&0xF], hexDigits[unit>>4&0xF], hexDigits[unit&0xF])
}

var shortEscapes = map[uint16]string{
	'"': `\"`, '\\': `\\`, '\b': `\b`, '\f': `\f`, '\n': `\n`, '\r': `\r`, '\t': `\t`,
}

// appendString writes a JSON string the way ECMAScript JSON.stringify does: short escapes, \u00xx
// for other control characters, \udxxx for a lone surrogate, everything else as UTF-8.
func appendString(out []byte, units []uint16) []byte {
	out = append(out, '"')
	for i := 0; i < len(units); i++ {
		unit := units[i]
		if short, ok := shortEscapes[unit]; ok {
			out = append(out, short...)
			continue
		}
		switch {
		case unit < 0x20:
			out = appendUnicodeEscape(out, unit)
		case isHighSurrogate(unit) && i+1 < len(units) && isLowSurrogate(units[i+1]):
			point := 0x10000 + (rune(unit)-0xD800)<<10 + (rune(units[i+1]) - 0xDC00)
			out = utf8.AppendRune(out, point)
			i++
		case isSurrogate(unit):
			out = appendUnicodeEscape(out, unit)
		default:
			out = utf8.AppendRune(out, rune(unit))
		}
	}
	return append(out, '"')
}

// appendNumber writes a double as ECMAScript Number::toString does. A non-finite number is
// `null`, as JSON.stringify writes it.
func appendNumber(out []byte, value float64) []byte {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return append(out, "null"...)
	}
	if value == 0 {
		return append(out, '0')
	}
	if value < 0 {
		out = append(out, '-')
		value = -value
	}
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	mantissa, exponentText, _ := strings.Cut(scientific, "e")
	exponent, _ := strconv.Atoi(exponentText)
	digits := strings.Replace(mantissa, ".", "", 1)
	return append(out, formatDigits(digits, exponent+1)...)
}

// formatDigits places the shortest digits: `point` is the position of the decimal point
// (ECMAScript n): plain notation for -6 < n <= 21, an exponent otherwise.
func formatDigits(digits string, point int) string {
	count := len(digits)
	switch {
	case count <= point && point <= 21:
		return digits + strings.Repeat("0", point-count)
	case 0 < point && point <= 21:
		return digits[:point] + "." + digits[point:]
	case -6 < point && point <= 0:
		return "0." + strings.Repeat("0", -point) + digits
	}
	return exponential(digits, point-1)
}

func exponential(digits string, exponent int) string {
	sign := "+"
	if exponent < 0 {
		sign = "-"
		exponent = -exponent
	}
	mantissa := digits[:1]
	if len(digits) > 1 {
		mantissa += "." + digits[1:]
	}
	return mantissa + "e" + sign + strconv.Itoa(exponent)
}

type writeFrame struct {
	node  *node
	index int
}

// marshal writes the value as compact JSON, iteratively.
func marshal(root *node) []byte {
	var out []byte
	stack := []writeFrame{{node: root}}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		var child *node
		out, child = writeStep(out, top)
		if child == nil && top.index < 0 {
			stack = stack[:len(stack)-1]
			continue
		}
		if child != nil {
			stack = append(stack, writeFrame{node: child})
		}
	}
	return out
}

// writeStep writes the next piece of the frame's value. It returns the child container to enter,
// if any; a finished frame has index -1.
func writeStep(out []byte, top *writeFrame) ([]byte, *node) {
	value := top.node
	if top.index == 0 {
		switch value.kind {
		case kindNull:
			return finishWith(out, top, "null"), nil
		case kindBool:
			return finishWith(out, top, strconv.FormatBool(value.flag)), nil
		case kindNumber:
			out = appendNumber(out, value.num)
			top.index = -1
			return out, nil
		case kindString:
			out = appendString(out, value.str)
			top.index = -1
			return out, nil
		case kindArray:
			out = append(out, '[')
		case kindObject:
			out = append(out, '{')
		}
	}
	return writeEntry(out, top)
}

func finishWith(out []byte, top *writeFrame, literal string) []byte {
	top.index = -1
	return append(out, literal...)
}

func entryCount(value *node) int {
	if value.kind == kindArray {
		return len(value.items)
	}
	return len(value.members)
}

// writeEntry writes the separator and key of the next entry, or the closing bracket.
func writeEntry(out []byte, top *writeFrame) ([]byte, *node) {
	value := top.node
	entry := top.index
	if entry >= entryCount(value) {
		top.index = -1
		return append(out, closer(value)...), nil
	}
	if entry > 0 {
		out = append(out, ',')
	}
	top.index++
	if value.kind == kindArray {
		return out, value.items[entry]
	}
	out = appendString(out, value.members[entry].key)
	out = append(out, ':')
	return out, value.members[entry].val
}

func closer(value *node) string {
	if value.kind == kindArray {
		return "]"
	}
	return "}"
}
