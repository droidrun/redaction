package redaction

import (
	"encoding/base64"
	"strings"
)

// The 1Password check (SPEC 5.7): a token body is base64 whose bytes, read as Latin-1, are one JSON
// object or array. The syntax check is the one of the JSON reader of the package (no depth limit, no
// recursion, no library dialects: `NaN`, trailing commas and trailing text are refused).

const (
	base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	base64Group    = 4
	base64Pad      = '='
)

// decodeBase64 is the forgiving decode of the WHATWG spec: up to two trailing `=` only when the
// length is a multiple of 4; a length of 1 modulo 4 fails, and so does every unit outside the
// alphabet (an `=` left in the middle too). Bits that do not fill a byte are dropped.
func decodeBase64(input []uint16) ([]byte, bool) {
	data := input
	if len(data)%base64Group == 0 {
		for pads := 0; pads < 2 && len(data) > 0 && data[len(data)-1] == base64Pad; pads++ {
			data = data[:len(data)-1]
		}
	}
	encoded := make([]byte, len(data))
	for i, unit := range data {
		if unit >= 0x80 || strings.IndexByte(base64Alphabet, byte(unit)) < 0 {
			return nil, false
		}
		encoded[i] = byte(unit)
	}
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(encoded)))
	length, err := base64.RawStdEncoding.Decode(decoded, encoded)
	return decoded[:length], err == nil
}

// isJSONContainer is true when the bytes are one JSON text whose top value is an object or an array.
func isJSONContainer(data []byte) bool {
	reader := &parser{data: data}
	reader.skipSpace()
	if opening, ok := reader.peek(); !ok || (opening != '{' && opening != '[') {
		return false
	}
	if reader.skipValue() != nil {
		return false
	}
	reader.skipSpace()
	return reader.at == len(data)
}

// isBase64JSON is true when the token decodes as base64 to bytes that are a JSON object or an array.
func isBase64JSON(token []uint16) bool {
	data, ok := decodeBase64(token)
	return ok && isJSONContainer(data)
}
