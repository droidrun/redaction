package redaction

// evidence holds the parameters of value evidence, trivial values and documentation stand-ins
// (SPEC 5.4 and 5.5), all from algorithms.json.
type evidence struct {
	quotes       []uint16
	classes      []*unitSet
	minClasses   int
	threshold    float64
	trivialWords map[string]bool
	maskChars    []uint16
	wrappers     [][2]uint16
	wrapperInner *unitSet
	docPrefixes  [][]uint16
	docSuffixes  [][]uint16
	docSeparator *unitSet
	whitespace   *unitSet
	placeholders *placeholders
}

const (
	upperKelvin = 0x212A
	upperDotI   = 0x0130
)

// lowerUnit is the spec's `lower`: A to Z become a to z, KELVIN SIGN becomes k, nothing else changes.
func lowerUnit(unit uint16) uint16 {
	if unit >= 'A' && unit <= 'Z' {
		return unit + ('a' - 'A')
	}
	if unit == upperKelvin {
		return 'k'
	}
	return unit
}

// foldString is lower(x) as a Go string. Units above ASCII keep their identity, so a comparison
// with an ASCII word list is exact.
func foldString(units []uint16) string {
	runes := make([]rune, len(units))
	for i, unit := range units {
		runes[i] = rune(lowerUnit(unit))
	}
	return string(runes)
}

func (v *evidence) trim(units []uint16) []uint16 {
	start := 0
	end := len(units)
	for start < end && v.whitespace.has(units[start]) {
		start++
	}
	for end > start && v.whitespace.has(units[end-1]) {
		end--
	}
	return units[start:end]
}

func (v *evidence) lowerTrimmed(raw []uint16) []uint16 {
	return lowerUnits(v.trim(raw))
}

// lowerUnits is a lower-cased copy (the spec's `lower`).
func lowerUnits(units []uint16) []uint16 {
	lowered := make([]uint16, len(units))
	for i, unit := range units {
		lowered[i] = lowerUnit(unit)
	}
	return lowered
}

func isRepeatOf(units []uint16, mask uint16) bool {
	for _, unit := range units {
		if unit != mask {
			return false
		}
	}
	return len(units) > 0
}

func (v *evidence) isMask(units []uint16) bool {
	for _, mask := range v.maskChars {
		if isRepeatOf(units, mask) {
			return true
		}
	}
	return false
}

func (v *evidence) isWrapped(units []uint16) bool {
	if len(units) < 2 {
		return false
	}
	first := units[0]
	last := units[len(units)-1]
	for _, pair := range v.wrappers {
		if first == pair[0] && last == pair[1] && v.hasOnlyInnerUnits(units[1:len(units)-1]) {
			return true
		}
	}
	return false
}

func (v *evidence) hasOnlyInnerUnits(inner []uint16) bool {
	for _, unit := range inner {
		if !v.wrapperInner.has(unit) {
			return false
		}
	}
	return true
}

// isTrivialValue is true for deny-listed stand-ins: `null`, `changeme`, `xxxxxxxx`, `<secret>`.
func (v *evidence) isTrivialValue(raw []uint16) bool {
	value := v.lowerTrimmed(raw)
	if v.trivialWords[foldString(value)] {
		return true
	}
	return v.isMask(value) || v.isWrapped(value)
}

func (v *evidence) hasSeparatorAfter(value []uint16, prefix []uint16) bool {
	if !hasUnitsAt(value, prefix, 0) || len(value) <= len(prefix) {
		return false
	}
	return v.docSeparator.has(value[len(prefix)])
}

func (v *evidence) startsWithDocPrefix(value []uint16) bool {
	for _, prefix := range v.docPrefixes {
		if v.hasSeparatorAfter(value, prefix) {
			return true
		}
	}
	return false
}

func (v *evidence) endsWithDocSuffix(value []uint16) bool {
	for _, suffix := range v.docSuffixes {
		at := len(value) - len(suffix) - 1
		if at >= 0 && hasUnitsAt(value, suffix, at+1) && v.docSeparator.has(value[at]) {
			return true
		}
	}
	return false
}

// isDocPlaceholder is true for documentation stand-ins: `your_api_key_here`, `REPLACE_ME_TOKEN`.
func (v *evidence) isDocPlaceholder(raw []uint16) bool {
	value := v.lowerTrimmed(raw)
	return v.startsWithDocPrefix(value) || v.endsWithDocSuffix(value)
}

func (v *evidence) isQuote(unit uint16) bool {
	for _, quote := range v.quotes {
		if unit == quote {
			return true
		}
	}
	return false
}

// stripQuotes removes one leading and one trailing quote unit, each independently.
func (v *evidence) stripQuotes(raw []uint16) []uint16 {
	value := raw
	if len(value) > 0 && v.isQuote(value[0]) {
		value = value[1:]
	}
	if len(value) > 0 && v.isQuote(value[len(value)-1]) {
		value = value[:len(value)-1]
	}
	return value
}

func (v *evidence) classCount(units []uint16) int {
	count := 0
	for _, class := range v.classes {
		if class.hasAnyIn(units) {
			count++
		}
	}
	return count
}

// hasValueEvidence: enough character classes, or high enough entropy; trivial values and our own
// placeholders never count.
func (v *evidence) hasValueEvidence(raw []uint16) bool {
	value := v.stripQuotes(raw)
	if v.placeholders.isWhole(value) || v.isTrivialValue(value) {
		return false
	}
	if v.classCount(value) >= v.minClasses {
		return true
	}
	return shannonEntropy(value) >= v.threshold
}

// shannonEntropy is the entropy in bits per symbol (a code point; a lone surrogate is one
// symbol), divided by the UTF-16 length, summed in first-occurrence order (SPEC 5.4).
func shannonEntropy(units []uint16) float64 {
	length := len(units)
	if length == 0 {
		return 0
	}
	index := make(map[uint32]int)
	var counts []int
	for i := 0; i < length; i++ {
		symbol := uint32(units[i])
		if isHighSurrogate(units[i]) && i+1 < length && isLowSurrogate(units[i+1]) {
			symbol = uint32(pairPoint(units[i], units[i+1]))
			i++
		}
		at, seen := index[symbol]
		if !seen {
			at = len(counts)
			index[symbol] = at
			counts = append(counts, 0)
		}
		counts[at]++
	}
	entropy := 0.0
	for _, count := range counts {
		probability := float64(count) / float64(length)
		entropy -= float64(probability * log2fdlibm(probability))
	}
	return entropy
}
