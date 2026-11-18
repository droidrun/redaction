package redaction

import "strings"

type verdict int

const (
	verdictNone verdict = iota
	verdictString
	verdictAny
)

// keyNames is the key-name matcher of SPEC section 6, from keys.json.
type keyNames struct {
	sequences    [][]string
	exact        map[string]bool
	joined       map[string]bool
	suffixWords  []string
	prefixWords  []string
	passLastWord string
	countWords   map[string]bool
	skipKeys     []string
	placeholders *placeholders
}

func newKeyNames(keys *keysFile, found *placeholders) *keyNames {
	sequences := append(append([][]string{}, keys.SecretWords...), keys.ExtraSequences...)
	joined := make(map[string]bool)
	for _, sequence := range sequences {
		if len(sequence) > 1 {
			joined[strings.Join(sequence, "")] = true
		}
	}
	for _, word := range keys.JoinedExtra {
		joined[word] = true
	}
	return &keyNames{
		sequences:    sequences,
		exact:        toSet(keys.ExactKeys),
		joined:       joined,
		suffixWords:  keys.SuffixWords,
		prefixWords:  keys.PrefixWords,
		passLastWord: keys.PassLastWord,
		countWords:   toSet(keys.CountWords),
		skipKeys:     keys.StructuralSkipKeys,
		placeholders: found,
	}
}

func toSet(words []string) map[string]bool {
	set := make(map[string]bool, len(words))
	for _, word := range words {
		set[word] = true
	}
	return set
}

func isUpperUnit(units []uint16, at int) bool {
	return at < len(units) && units[at] >= 'A' && units[at] <= 'Z'
}

func isLowerUnit(units []uint16, at int) bool {
	return at < len(units) && units[at] >= 'a' && units[at] <= 'z'
}

func isDigitUnit(units []uint16, at int) bool {
	return at < len(units) && units[at] >= '0' && units[at] <= '9'
}

func runWhile(units []uint16, from int, test func([]uint16, int) bool) int {
	end := from
	for test(units, end) {
		end++
	}
	return end
}

// wordEnd is the end of the word that starts at `start`, or `start` when none does (SPEC 6).
func wordEnd(key []uint16, start int) int {
	if isUpperUnit(key, start) {
		capitals := runWhile(key, start, isUpperUnit)
		if !isLowerUnit(key, capitals) {
			return capitals
		}
		if capitals-start >= 2 {
			return capitals - 1
		}
	}
	lowerStart := start
	if isUpperUnit(key, start) {
		lowerStart = start + 1
	}
	lowerEnd := runWhile(key, lowerStart, isLowerUnit)
	if lowerEnd > lowerStart {
		return lowerEnd
	}
	if isDigitUnit(key, start) {
		return runWhile(key, start, isDigitUnit)
	}
	return start
}

// splitKeyWords splits a key into lower-case words at separators and camelCase humps.
func splitKeyWords(key []uint16) []string {
	var words []string
	for at := 0; at < len(key); {
		end := wordEnd(key, at)
		if end == at {
			at++
			continue
		}
		words = append(words, foldString(key[at:end]))
		at = end
	}
	return words
}

// compactKey is the key lower-cased with every unit outside a-z and 0-9 removed (U+0130 is `i`).
func compactKey(key []uint16) string {
	var compact []byte
	for _, unit := range key {
		lowered := lowerUnit(unit)
		if unit == upperDotI {
			lowered = 'i'
		}
		isLetter := lowered >= 'a' && lowered <= 'z'
		isDigit := lowered >= '0' && lowered <= '9'
		if isLetter || isDigit {
			compact = append(compact, byte(lowered))
		}
	}
	return string(compact)
}

func (k *keyNames) isSecretWord(word string, plural bool) bool {
	base := word
	if plural {
		base = strings.TrimSuffix(word, "s")
	}
	if k.joined[word] || k.joined[base] {
		return true
	}
	for _, suffix := range k.suffixWords {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	for _, prefix := range k.prefixWords {
		if strings.HasPrefix(word, prefix) {
			return true
		}
	}
	return false
}

func wordMatches(words []string, at int, expected string, plural bool) bool {
	if at >= len(words) {
		return false
	}
	return words[at] == expected || (plural && words[at] == expected+"s")
}

func startsSequence(words []string, start int, sequence []string, plural bool) bool {
	for offset, expected := range sequence {
		if !wordMatches(words, start+offset, expected, plural) {
			return false
		}
	}
	return true
}

func (k *keyNames) hasSequence(words []string, plural bool) bool {
	for _, sequence := range k.sequences {
		for start := range words {
			if startsSequence(words, start, sequence, plural) {
				return true
			}
		}
	}
	return false
}

func (k *keyNames) matchKey(key []uint16, plural bool) bool {
	words := splitKeyWords(key)
	if k.exact[compactKey(key)] {
		return true
	}
	if len(words) > 0 && words[len(words)-1] == k.passLastWord {
		return true
	}
	for _, word := range words {
		if k.isSecretWord(word, plural) {
			return true
		}
	}
	return k.hasSequence(words, plural)
}

func (k *keyNames) isSecretKeyName(key []uint16) bool {
	return k.matchKey(key, true)
}

var redactedOpen = asUnits("[REDACTED")

// keyVerdict is what a key makes of the values below it. A key that holds placeholders is
// classified without them, so a second pass gives the first verdict.
func (k *keyNames) keyVerdict(raw []uint16) verdict {
	key := raw
	if containsUnits(raw, redactedOpen) {
		key = joinSegments(k.placeholders.literalSegments(newText(raw)))
	}
	if !k.matchKey(key, true) {
		return verdictNone
	}
	if !k.matchKey(key, false) {
		return verdictString
	}
	for _, word := range splitKeyWords(key) {
		if k.countWords[word] {
			return verdictString
		}
	}
	return verdictAny
}

func joinSegments(segments [][]uint16) []uint16 {
	var joined []uint16
	for i, segment := range segments {
		if i > 0 {
			joined = append(joined, ' ')
		}
		joined = append(joined, segment...)
	}
	return joined
}

func strongerVerdict(a verdict, b verdict) verdict {
	return max(a, b)
}
