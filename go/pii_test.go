package redaction

import "testing"

// Keys that only strict or the `PII` option redact (SPEC 8, 9.3, 9.5). The literal values are those of the
// TypeScript package; the vectors in spec/vectors/pii.json cover the texts.

func TestKeysRedactedByPIIKeepTheirValues(t *testing.T) {
	const emails = `{"bob@example.com":{"n":1},"alice@example.com":{"n":2}}`
	for _, tier := range []Tier{TierStandard, TierFull} {
		runJSONCases(t, []jsonCase{
			{
				"emails as keys are numbered", emails, Options{Tier: tier, PII: true},
				`{"[REDACTED:email]":{"n":1},"[REDACTED:email#2]":{"n":2}}`,
			},
			{"the option off leaves the keys", emails, Options{Tier: tier}, emails},
			{
				"compat with the option", emails, Options{Tier: tier, Mode: Compat, PII: true},
				`{"[REDACTED:email]":{"n":1},"[REDACTED:email#2]":{"n":2}}`,
			},
			{
				"a key shorter than eight units is scanned with the option", `{"a@b.xx":1}`,
				Options{Tier: tier, Mode: Compat, PII: true}, `{"[REDACTED:email]":1}`,
			},
			{
				"a key shorter than eight units is not scanned without it", `{"a@b.xx":1}`,
				Options{Tier: tier, Mode: Compat}, `{"a@b.xx":1}`,
			},
		})
	}
}

func TestKeysOnlyStrictRedacts(t *testing.T) {
	const keys = `{"token=hunter2":"v","dr_sk_first1":"w"}`
	for _, tier := range []Tier{TierStandard, TierFull} {
		runJSONCases(t, []jsonCase{
			{
				"strict", keys, Options{Tier: tier},
				`{"token=[REDACTED:generic-keyword]":"[REDACTED:key-context]","[REDACTED:platform-key]":"w"}`,
			},
			{
				"compat", keys, Options{Tier: tier, Mode: Compat},
				`{"token=hunter2":"[REDACTED:key-context]","dr_sk_first1":"w"}`,
			},
			{
				"strict and the option", `{"bob@example.com":1,"token=hunter2":2}`,
				Options{Tier: tier, PII: true},
				`{"[REDACTED:email]":1,"token=[REDACTED:generic-keyword]":"[REDACTED:key-context]"}`,
			},
		})
	}
}

func TestPIIHitsCarryTheirOwnRuleIDs(t *testing.T) {
	out, result := RedactText("mail a@b.xx from 192.0.2.123, code: 482913", Options{PII: true})
	want := "mail [REDACTED:email] from [REDACTED:ip], code: [REDACTED:otp]"
	if out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	counts := countsOf(result)
	if counts["email"] != 1 || counts["ip"] != 1 || counts["otp"] != 1 || len(counts) != 3 {
		t.Fatalf("got %v", counts)
	}
}
