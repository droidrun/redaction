package redaction

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

const injectedMarker = "Zq9LEAKcheck77_x"

func TestResultHoldsRuleIdsAndCountsOnly(t *testing.T) {
	result := reflect.TypeOf(Result{})
	if result.NumField() != 2 || result.Field(0).Name != "Hits" || result.Field(1).Name != "Err" {
		t.Fatal("Result has fields other than Hits and Err")
	}
	count := reflect.TypeOf(RuleCount{})
	if count.NumField() != 2 || count.Field(0).Name != "RuleID" || count.Field(1).Name != "Count" {
		t.Fatal("RuleCount has fields other than RuleID and Count")
	}
}

func TestResultNeverHoldsMatchedText(t *testing.T) {
	inputs := []string{
		"password=" + injectedMarker,
		"Authorization: Bearer " + injectedMarker,
		strings.Repeat("a", 40) + " password=" + injectedMarker,
	}
	for _, input := range inputs {
		out, result := RedactText(input, Options{})
		if strings.Contains(out, injectedMarker) {
			t.Fatalf("marker survives in %q", out)
		}
		if strings.Contains(result.Err, injectedMarker) {
			t.Fatal("marker in Err")
		}
		for _, entry := range result.Hits {
			if strings.Contains(entry.RuleID, injectedMarker) {
				t.Fatal("marker in a rule id")
			}
		}
	}
	_, result := RedactText("password="+injectedMarker, Options{MaxChars: Limit(8)})
	if result.Err != "size-limit" || len(result.Hits) != 1 || result.Hits[0].RuleID != "size-limit" {
		t.Fatalf("got %+v", result)
	}
}

func TestErrorsNameNoInput(t *testing.T) {
	inputs := []string{`{"password":"` + injectedMarker + `"`, injectedMarker, `{"a":` + injectedMarker + `}`}
	for _, input := range inputs {
		_, _, err := RedactJSON([]byte(input), Options{})
		if err == nil || strings.Contains(err.Error(), injectedMarker) {
			t.Fatalf("got %v", err)
		}
	}
}

func TestFailureEventsCarryTheClassOnly(t *testing.T) {
	out, result, err := RedactJSON([]byte(`{"a":{"b":"`+injectedMarker+`"}}`), Options{MaxDepth: Limit(1)})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"a":"[REDACTED:depth-limit]"}` || result.Err != "depth-limit" {
		t.Fatalf("got %s with %+v", out, result)
	}
}

func TestIsSecretKeyName(t *testing.T) {
	secret := []string{
		"apiKey", "api_key", "client_secret", "x-auth-token", "Set-Cookie", "pin", "tokens", "DB_PASSWORD",
	}
	plain := []string{"secretary", "tokenizer", "passwordless", "name", ""}
	for _, key := range secret {
		if !IsSecretKeyName(key) {
			t.Fatalf("%q should name a secret", key)
		}
	}
	for _, key := range plain {
		if IsSecretKeyName(key) {
			t.Fatalf("%q should not name a secret", key)
		}
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := 0; i < 20; i++ {
				out, _ := RedactText("x password="+injectedMarker+" Bearer abc.def-1=xyz", Options{})
				if strings.Contains(out, injectedMarker) {
					t.Error("marker survives")
				}
				if _, _, err := RedactJSON([]byte(`{"token":"`+injectedMarker+`"}`), Options{}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	group.Wait()
}
