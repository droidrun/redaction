package redaction

import (
	"encoding/json"
	"reflect"
)

// KeyVerdict says what the key name makes of the values below it: VerdictNone, VerdictString
// (a string is replaced, a number is kept: `tokens`, `max_tokens`) or VerdictAny (a string and a
// number are replaced: `password`, `pin`). It is the verdict RedactJSON uses for an object key.
func KeyVerdict(key string) Verdict {
	return theEngine.keys.keyVerdict(decodeUTF8(key))
}

// RedactField redacts the value of one attribute (a log field, a span attribute) by its key, the
// way RedactJSON treats an object member: a string under a secret-named key is replaced by
// `[REDACTED:key-context]`, any other string is scanned like RedactText with the default
// options, and a number is replaced only under a key whose verdict is VerdictAny, so counts such
// as `max_tokens` stay. Every other type (bool, nil, a struct, an error) is returned as it is:
// turn it into a string first, or marshal it and use RedactJSON. The returned value has the type
// of the input, except that a replaced number is the placeholder string.
func RedactField(key string, value any) any {
	verdict := KeyVerdict(key)
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return redactFieldText(verdict, typed)
	case json.Number:
		return redactFieldNumber(verdict, value)
	}
	switch reflect.ValueOf(value).Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return redactFieldNumber(verdict, value)
	case reflect.String:
		return redactFieldText(verdict, reflect.ValueOf(value).String())
	}
	return value
}

func redactFieldNumber(verdict Verdict, value any) any {
	if verdict != VerdictAny {
		return value
	}
	return theEngine.placeholders.read(theEngine.spec.algorithms.RuleIDs.KeyContext)
}

func redactFieldText(verdict Verdict, text string) string {
	if verdict == VerdictNone {
		out, _ := RedactText(text, Options{})
		return out
	}
	if text == "" || theEngine.placeholders.isWhole(decodeUTF8(text)) {
		return text
	}
	return theEngine.placeholders.read(theEngine.spec.algorithms.RuleIDs.KeyContext)
}
