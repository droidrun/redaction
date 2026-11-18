package redaction

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// searchersOf lists the searcher of every rule of the standard pipeline by rule id, and of every
// full-tier rule by `full:` and its id (a rule with two, such as auth-values, lists both).
func searchersOf(t *testing.T) map[string][]*searcher {
	t.Helper()
	found := make(map[string][]*searcher)
	collect := func(prefix string, entries []pipelineEntry) {
		for _, entry := range entries {
			id := prefix + entry.id
			switch rule := entry.scanner.(type) {
			case *regexRule:
				found[id] = append(found[id], rule.search)
			case *pemBlocks:
				found[id] = append(found[id], rule.header)
			case *pemKey:
				found[id] = append(found[id], rule.header)
			case *credentialURI:
				found[id] = append(found[id], rule.search)
			case *cookieLines:
				found[id] = append(found[id], rule.search)
			case *authValues:
				found[id] = append(found[id], rule.bearer, rule.scheme)
			case *keywordPairs:
				found[id] = append(found[id], rule.search)
			case *quotedPairs:
				found[id] = append(found[id], rule.search)
			case *unquotedPairs:
				found[id] = append(found[id], rule.search)
			case *queryValues:
				found[id] = append(found[id], rule.search)
			}
		}
	}
	collect("", theEngine.pipeline)
	collect("full:", theEngine.full)
	return found
}

func sortedCopy(values []string) []string {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return sorted
}

func TestRequiredLiteralsOfTheSpecPatterns(t *testing.T) {
	cases := map[string][]string{
		"gcp-api-key":     {"aiza"},
		"xai-api-key":     {"xai-"},
		"platform-token":  {"srt"},
		"platform-key":    {"dr_sk_"},
		"aws":             {"akia", "asia"},
		"slack":           {"xoxa-", "xoxb-", "xoxo-", "xoxp-", "xoxr-", "xoxs-"},
		"stripe":          {"rk_live_", "rk_test_", "sk_live_", "sk_test_"},
		"private-key":     {"private key-----"},
		"openai":          {"sk-"},
		"url-credentials": {"://"},
		"cookie":          {"cookie", "set-cookie"},
		"github":          {"hp_", "ho_", "hu_", "hs_", "hr_", "ithub_pat_"},
	}
	found := searchersOf(t)
	for id, want := range cases {
		if got := found[id][0].needs; !reflect.DeepEqual(sortedCopy(got), sortedCopy(want)) {
			t.Errorf("%s: got %v, want %v", id, got, want)
		}
	}
	for _, id := range []string{"generic-keyword", "key-context", "auth-header"} {
		for _, search := range found[id] {
			if len(search.needs) == 0 {
				t.Errorf("%s has no required literals", id)
			}
		}
	}
	if got := found["auth-header"][0].needs; !reflect.DeepEqual(got, []string{"bearer"}) {
		t.Errorf("bearer: got %v", got)
	}
}

func TestHoldsAnyFoldsAsciiCase(t *testing.T) {
	if !holdsAny(lowerASCII("Authorization: BEARER abc"), []string{"bearer"}) {
		t.Fatal("upper case is not folded")
	}
	if holdsAny(lowerASCII("nothing to see"), []string{"bearer", "token"}) {
		t.Fatal("found a literal that is not there")
	}
	if !holdsAny("anything", nil) {
		t.Fatal("no literals must not filter")
	}
}

// The required literals are sound: wherever a pattern matches, its text holds one of them. Every
// text of the vectors and of the golden corpus is checked against every searcher.
func TestRequiredLiteralsHoldWhereverAPatternMatches(t *testing.T) {
	searchers := searchersOf(t)
	check := func(input []byte) {
		tree := parseTree(t, input)
		if tree.kind != kindString {
			return
		}
		content := newText(tree.str)
		for id, list := range searchers {
			for _, search := range list {
				matches := search.plain.FindStringIndex(content.mapped) != nil
				if matches && !holdsAny(content.foldedText(), search.needs) {
					t.Fatalf("%s: a match without any of %v", id, search.needs)
				}
			}
		}
	}
	for _, file := range loadVectors(t) {
		for _, c := range file.Cases {
			if c.InputGen == nil {
				check(c.Input)
			}
		}
	}
	for _, c := range loadGolden(t).Cases {
		if c.Gen == nil {
			check(c.Input)
		}
	}
}

func TestPrefilterDoesNotChangeResults(t *testing.T) {
	searchers := searchersOf(t)
	saved := make(map[*searcher][]string)
	for _, list := range searchers {
		for _, search := range list {
			saved[search] = search.needs
		}
	}
	golden := loadGolden(t)
	run := func() []string {
		var outputs []string
		for _, c := range golden.Cases[:3000] {
			var text string
			if json.Unmarshal(c.Input, &text) != nil {
				continue
			}
			out, _ := RedactText(text, Options{Mode: Compat})
			outputs = append(outputs, out)
		}
		return outputs
	}
	with := run()
	for search := range saved {
		search.needs = nil
	}
	without := run()
	for search, needs := range saved {
		search.needs = needs
	}
	if len(with) < 1000 || !reflect.DeepEqual(with, without) {
		t.Fatalf("%d outputs, equal: %v", len(with), reflect.DeepEqual(with, without))
	}
}
