package redaction

import (
	"regexp/syntax"
	"strings"
)

// A pattern of the spec is searched in text that mostly holds none of its keywords. The literals
// that every match must contain are read from the parsed pattern, and a search is skipped when
// the text has none of them (ASCII case folded: a two-case class such as [pP] counts as `p`).
// The literals are data derived from the spec patterns, never written in code.

func lowerASCII(text string) string {
	for i := 0; i < len(text); i++ {
		if text[i] >= 'A' && text[i] <= 'Z' {
			return strings.Map(lowerRuneASCII, text)
		}
	}
	return text
}

func lowerRuneASCII(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// finiteCap bounds the number of strings a part may stand for, and classes the characters they
// may list; larger parts are not enumerated.
const (
	finiteCap = 64
	classCap  = 8
)

// finiteSet is the set of strings a node matches (lower-cased, so a class [aA] is `a`), when that
// set is small. An optional part includes the empty string.
func finiteSet(node *syntax.Regexp) ([]string, bool) {
	switch node.Op {
	case syntax.OpLiteral:
		return []string{lowerASCII(string(node.Rune))}, true
	case syntax.OpCharClass:
		return classSet(node.Rune)
	case syntax.OpCapture:
		return finiteSet(node.Sub[0])
	case syntax.OpEmptyMatch, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}, true
	case syntax.OpQuest:
		set, ok := finiteSet(node.Sub[0])
		return dedupeStrings(append([]string{""}, set...)), ok
	case syntax.OpConcat:
		return concatSet(node.Sub)
	case syntax.OpAlternate:
		return alternateSet(node.Sub)
	}
	return nil, false
}

// classSet lists the characters of a small class, lower-cased.
func classSet(ranges []rune) ([]string, bool) {
	var members []string
	for i := 0; i+1 < len(ranges); i += 2 {
		if int(ranges[i+1]-ranges[i]) >= classCap {
			return nil, false
		}
		for r := ranges[i]; r <= ranges[i+1]; r++ {
			members = append(members, lowerASCII(string(r)))
		}
	}
	members = dedupeStrings(members)
	return members, len(members) <= classCap
}

func alternateSet(alternatives []*syntax.Regexp) ([]string, bool) {
	var union []string
	for _, alternative := range alternatives {
		set, ok := finiteSet(alternative)
		if !ok {
			return nil, false
		}
		union = append(union, set...)
	}
	union = dedupeStrings(union)
	return union, len(union) <= finiteCap
}

func concatSet(parts []*syntax.Regexp) ([]string, bool) {
	product := []string{""}
	for _, part := range parts {
		set, ok := finiteSet(part)
		if !ok {
			return nil, false
		}
		if product, ok = crossProduct(product, set); !ok {
			return nil, false
		}
	}
	return product, true
}

func crossProduct(left []string, right []string) ([]string, bool) {
	if len(left)*len(right) > finiteCap {
		return nil, false
	}
	product := make([]string, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			product = append(product, a+b)
		}
	}
	return dedupeStrings(product), true
}

// score is the length of the shortest literal: the longer, the rarer in ordinary text. A set
// that holds the empty string requires nothing and scores zero.
func score(set []string) int {
	shortest := len(set[0])
	for _, literal := range set {
		shortest = min(shortest, len(literal))
	}
	return shortest
}

// requiredIn is a set of literals of which every match of the node holds at least one, or nil.
func requiredIn(node *syntax.Regexp) []string {
	if set, ok := finiteSet(node); ok && score(set) > 0 {
		return set
	}
	switch node.Op {
	case syntax.OpCapture, syntax.OpPlus:
		return requiredIn(node.Sub[0])
	case syntax.OpRepeat:
		if node.Min >= 1 {
			return requiredIn(node.Sub[0])
		}
	case syntax.OpConcat:
		return requiredInConcat(node.Sub)
	case syntax.OpAlternate:
		return requiredInAlternate(node.Sub)
	}
	return nil
}

// requiredInAlternate is the union of the alternatives' sets; one without a set voids it.
func requiredInAlternate(alternatives []*syntax.Regexp) []string {
	var union []string
	for _, alternative := range alternatives {
		set := requiredIn(alternative)
		if set == nil {
			return nil
		}
		union = append(union, set...)
	}
	return dedupeStrings(union)
}

// requiredInConcat takes the best set among the runs of adjacent small parts (their cross
// product) and the sets of the other parts.
func requiredInConcat(parts []*syntax.Regexp) []string {
	var best []string
	consider := func(set []string) {
		if set != nil && score(set) > 0 && (best == nil || score(set) > score(best)) {
			best = set
		}
	}
	run := []string{""}
	for _, part := range parts {
		set, ok := finiteSet(part)
		if ok {
			if next, fits := crossProduct(run, set); fits {
				run = next
				continue
			}
		}
		consider(run)
		consider(requiredIn(part))
		run = []string{""}
		if ok {
			run = set
		}
	}
	consider(run)
	return best
}

// requiredLiterals parses a pattern the way regexp does and returns its required literals.
func requiredLiterals(source string) ([]string, error) {
	parsed, err := syntax.Parse(source, syntax.Perl)
	if err != nil {
		return nil, err
	}
	return dedupeStrings(requiredIn(parsed)), nil
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	var unique []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			unique = append(unique, value)
		}
	}
	return unique
}

// holdsAny is true when the lower-cased text contains one of the literals (or there are none).
func holdsAny(folded string, literals []string) bool {
	if len(literals) == 0 {
		return true
	}
	for _, literal := range literals {
		if strings.Contains(folded, literal) {
			return true
		}
	}
	return false
}
