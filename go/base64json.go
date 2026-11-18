package redaction

// The 1Password check (SPEC 5.7): a token body is base64 whose bytes, read as Latin-1, are one JSON
// object or array. The decoder and the syntax check are written here, so every language gives the
// same answer (no library dialects, no depth limit).

const (
	base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	sextetBits     = 6
	byteBits       = 8
	base64Group    = 4
	base64Pad      = '='
)

// base64Value maps a unit to its sextet, or -1.
var base64Value = func() [128]int8 {
	var table [128]int8
	for i := range table {
		table[i] = -1
	}
	for i := 0; i < len(base64Alphabet); i++ {
		table[base64Alphabet[i]] = int8(i)
	}
	return table
}()

// decodeBase64 is the forgiving decode of the WHATWG spec: up to two trailing `=` only when the
// length is a multiple of 4; a length of 1 modulo 4 fails; every 6 bits give a byte and the bits
// that do not fill one are dropped.
func decodeBase64(input []uint16) ([]byte, bool) {
	data := input
	if len(data)%base64Group == 0 {
		for pads := 0; pads < 2 && len(data) > 0 && data[len(data)-1] == base64Pad; pads++ {
			data = data[:len(data)-1]
		}
	}
	if len(data)%base64Group == 1 {
		return nil, false
	}
	bytes := make([]byte, 0, len(data)*sextetBits/byteBits)
	buffer, bits := 0, 0
	for _, unit := range data {
		if unit >= uint16(len(base64Value)) || base64Value[unit] < 0 {
			return nil, false
		}
		buffer = buffer<<sextetBits | int(base64Value[unit])
		bits += sextetBits
		if bits >= byteBits {
			bits -= byteBits
			bytes = append(bytes, byte(buffer>>bits))
			buffer &= 1<<bits - 1
		}
	}
	return bytes, true
}

const (
	jsonTab            = 0x09
	jsonLineFeed       = 0x0A
	jsonCarriageReturn = 0x0D
	jsonSpace          = 0x20
	jsonQuote          = '"'
	jsonBackslash      = '\\'
	jsonEndOfInput     = -1
)

// jsonBytes reads ECMA-404 syntax from bytes.
type jsonBytes struct {
	data []byte
	at   int
}

func (j *jsonBytes) peek() int {
	if j.at >= len(j.data) {
		return jsonEndOfInput
	}
	return int(j.data[j.at])
}

func (j *jsonBytes) skipSpace() {
	for {
		switch j.peek() {
		case jsonSpace, jsonTab, jsonLineFeed, jsonCarriageReturn:
			j.at++
		default:
			return
		}
	}
}

func isDigitByteValue(b int) bool {
	return b >= '0' && b <= '9'
}

func isHexByteValue(b int) bool {
	return isDigitByteValue(b) || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f')
}

func isJSONEscape(b int) bool {
	switch b {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return true
	}
	return false
}

// readString reads a string; the opening quote is at the current position.
func (j *jsonBytes) readString() bool {
	j.at++
	for {
		b := j.peek()
		j.at++
		if b == jsonEndOfInput || b < jsonSpace {
			return false
		}
		if b == jsonQuote {
			return true
		}
		if b != jsonBackslash {
			continue
		}
		escape := j.peek()
		j.at++
		if escape != 'u' {
			if !isJSONEscape(escape) {
				return false
			}
			continue
		}
		for digit := 0; digit < base64Group; digit++ {
			if !isHexByteValue(j.peek()) {
				return false
			}
			j.at++
		}
	}
}

func (j *jsonBytes) readDigits() bool {
	if !isDigitByteValue(j.peek()) {
		return false
	}
	for isDigitByteValue(j.peek()) {
		j.at++
	}
	return true
}

func (j *jsonBytes) readNumber() bool {
	if j.peek() == '-' {
		j.at++
	}
	if j.peek() == '0' {
		j.at++
	} else if !j.readDigits() {
		return false
	}
	if j.peek() == '.' {
		j.at++
		if !j.readDigits() {
			return false
		}
	}
	if j.peek() == 'e' || j.peek() == 'E' {
		j.at++
		if j.peek() == '+' || j.peek() == '-' {
			j.at++
		}
		if !j.readDigits() {
			return false
		}
	}
	return true
}

func (j *jsonBytes) readLiteral() bool {
	for _, word := range []string{"true", "false", "null"} {
		if j.at+len(word) <= len(j.data) && string(j.data[j.at:j.at+len(word)]) == word {
			j.at += len(word)
			return true
		}
	}
	return false
}

// readKey reads `"key"` and `:`, the start of an object member.
func (j *jsonBytes) readKey() bool {
	j.skipSpace()
	if j.peek() != jsonQuote || !j.readString() {
		return false
	}
	j.skipSpace()
	if j.peek() != ':' {
		return false
	}
	j.at++
	return true
}

func (j *jsonBytes) readScalar() bool {
	b := j.peek()
	switch {
	case b == jsonQuote:
		return j.readString()
	case b == '-' || isDigitByteValue(b):
		return j.readNumber()
	}
	return j.readLiteral()
}

type jsonStep int

const (
	stepBad jsonStep = iota
	stepValue
	stepClosed
)

// open reads an opening bracket: an empty container closes at once, else the first member (or
// value) starts. `stack` holds the open containers (true = object).
func (j *jsonBytes) open(stack *[]bool, bracket int) jsonStep {
	isObject := bracket == '{'
	j.at++
	*stack = append(*stack, isObject)
	j.skipSpace()
	closer := ']'
	if isObject {
		closer = '}'
	}
	if j.peek() == int(closer) {
		j.at++
		*stack = (*stack)[:len(*stack)-1]
		return stepClosed
	}
	if isObject && !j.readKey() {
		return stepBad
	}
	return stepValue
}

// after reads what follows a value: `,` and the next member, or the closing bracket of the
// innermost container.
func (j *jsonBytes) after(stack *[]bool) jsonStep {
	inObject := (*stack)[len(*stack)-1]
	b := j.peek()
	if b == ',' {
		j.at++
		if inObject && !j.readKey() {
			return stepBad
		}
		return stepValue
	}
	closer := ']'
	if inObject {
		closer = '}'
	}
	if b != int(closer) {
		return stepBad
	}
	j.at++
	*stack = (*stack)[:len(*stack)-1]
	return stepClosed
}

// isJSONContainer is true when the bytes are one JSON text whose top value is an object or an
// array. Iterative: no depth limit and no recursion.
func isJSONContainer(data []byte) bool {
	reader := &jsonBytes{data: data}
	reader.skipSpace()
	if reader.peek() != '{' && reader.peek() != '[' {
		return false
	}
	var stack []bool
	expectValue := true
	for expectValue || len(stack) > 0 {
		reader.skipSpace()
		b := reader.peek()
		var step jsonStep
		switch {
		case !expectValue:
			step = reader.after(&stack)
		case b == '{' || b == '[':
			step = reader.open(&stack, b)
		case reader.readScalar():
			step = stepClosed
		}
		if step == stepBad {
			return false
		}
		expectValue = step == stepValue
	}
	reader.skipSpace()
	return reader.peek() == jsonEndOfInput
}

// isBase64JSON is true when the token decodes as base64 to bytes that are a JSON object or array.
func isBase64JSON(token []uint16) bool {
	data, ok := decodeBase64(token)
	return ok && isJSONContainer(data)
}
