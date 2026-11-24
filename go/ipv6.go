package redaction

import "strings"

// ipv6Groups is the number of groups of an IPv6 address (RFC 4291).
const ipv6Groups = 8

const (
	maxGroupDigits = 4
	listSeparator  = ":"
	compression    = "::"
)

func isHexDigit(char rune) bool {
	return (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')
}

// isGroup is true for 1 to 4 hexadecimal digits.
func isGroup(group string) bool {
	if len(group) < 1 || len(group) > maxGroupDigits {
		return false
	}
	return strings.IndexFunc(group, func(char rune) bool { return !isHexDigit(char) }) < 0
}

// areGroups is true when every group of a list separated by colons is valid.
func areGroups(list string) bool {
	for _, group := range strings.Split(list, listSeparator) {
		if !isGroup(group) {
			return false
		}
	}
	return true
}

// sideGroups is the number of groups of one side of `::`: none for an empty side; ok is false when a
// group is not valid.
func sideGroups(side string) (count int, ok bool) {
	if side == "" {
		return 0, true
	}
	return strings.Count(side, listSeparator) + 1, areGroups(side)
}

// isIpv6 is the `ipv6` check of SPEC 5.8: whether a run of hexadecimal digits and colons is the text
// form of an IPv6 address (RFC 4291 section 2.2, RFC 5952). `minColons` is how many colons the text
// needs at least.
func isIpv6(text string, minColons int) bool {
	colons := strings.Count(text, listSeparator)
	if colons < minColons {
		return false
	}
	parts := strings.Split(text, compression)
	if len(parts) == 1 {
		return colons == ipv6Groups-1 && areGroups(text)
	}
	if len(parts) != 2 {
		return false
	}
	before, isBeforeValid := sideGroups(parts[0])
	after, isAfterValid := sideGroups(parts[1])
	return isBeforeValid && isAfterValid && before+after < ipv6Groups
}
