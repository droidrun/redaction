package redaction

import (
	"encoding/json"
	"testing"
)

type nameString string

type attribute struct{ Name string }

func TestKeyVerdict(t *testing.T) {
	cases := map[string]Verdict{
		"password":      VerdictAny,
		"pin":           VerdictAny,
		"x-auth-token":  VerdictAny,
		"tokens":        VerdictString,
		"max_tokens":    VerdictString,
		"prompt_tokens": VerdictString,
		"name":          VerdictNone,
		"secretary":     VerdictNone,
		"":              VerdictNone,
	}
	for key, want := range cases {
		if got := KeyVerdict(key); got != want {
			t.Errorf("%q: got %v, want %v", key, got, want)
		}
	}
}

func TestRedactField(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value any
		want  any
	}{
		{"secret string", "password", "hunter2xx", "[REDACTED:key-context]"},
		{"secret string, plural key", "tokens", "abc", "[REDACTED:key-context]"},
		{"empty string stays", "api_key", "", ""},
		{"placeholder stays", "token", "[REDACTED:key-context]", "[REDACTED:key-context]"},
		{"plain string is scanned", "note", "password=" + secretValue, "password=" + keyword},
		{"clean string stays", "note", "all fine here", "all fine here"},
		{"count stays", "max_tokens", 100, 100},
		{"count stays, float", "prompt_tokens", 12.5, 12.5},
		{"number under a secret key", "pin", 1234, "[REDACTED:key-context]"},
		{"uint8 under a secret key", "pin", uint8(7), "[REDACTED:key-context]"},
		{"float under a secret key", "password", 1.5, "[REDACTED:key-context]"},
		{"json.Number under a secret key", "pin", json.Number("1234"), "[REDACTED:key-context]"},
		{"json.Number elsewhere", "latency_ms", json.Number("42"), json.Number("42")},
		{"number elsewhere", "latency_ms", 42, 42},
		{"named string type", "password", nameString("hunter2xx"), "[REDACTED:key-context]"},
		{"bool stays", "password", true, true},
		{"nil stays", "password", nil, nil},
		{"struct stays", "password", attribute{"x"}, attribute{"x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedactField(c.key, c.value); got != c.want {
				t.Fatalf("got %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestRedactFieldAgreesWithRedactJSON(t *testing.T) {
	members := map[string]string{
		"password": `"hunter2xx"`, "max_tokens": `100`, "pin": `1234`,
		"note": `"password=` + secretValue + `"`,
	}
	values := map[string]any{
		"password": "hunter2xx", "max_tokens": 100, "pin": 1234, "note": "password=" + secretValue,
	}
	for key, literal := range members {
		out, _, err := RedactJSON([]byte(`{"`+key+`":`+literal+`}`), Options{})
		if err != nil {
			t.Fatal(err)
		}
		field, err := json.Marshal(map[string]any{key: RedactField(key, values[key])})
		if err != nil || string(out) != string(field) {
			t.Fatalf("%s: RedactJSON gave %s, RedactField gave %s", key, out, field)
		}
	}
}
