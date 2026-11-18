package redaction

import (
	"encoding/json"
	"regexp"
)

type credentialSpec struct {
	Pattern                string   `json:"pattern"`
	UserMin                int      `json:"userMin"`
	PasswordMin            int      `json:"passwordMin"`
	UserIgnoreContains     []string `json:"userIgnoreContains"`
	PasswordIgnoreContains []string `json:"passwordIgnoreContains"`
	PasswordIgnoreEquals   []string `json:"passwordIgnoreEquals"`
	UserEqualsPassword     bool     `json:"userEqualsPassword"`
	VariablePatterns       []string `json:"variablePatterns"`
	RepeatRun              int      `json:"repeatRun"`
}

// credentialURI is SPEC 4.15: URLs that carry `user:password@` and look real. The pattern's groups 1
// and 2 are the user and the password; a match that fails a check is consumed and not reported.
type credentialURI struct {
	search           *searcher
	userMin          int
	passwordMin      int
	userContains     [][]uint16
	passwordContains [][]uint16
	passwordEquals   [][]uint16
	userEqualsSecret bool
	variables        []*regexp.Regexp
	repeatRun        int
}

// foldedUnits is a lower-cased copy (the spec's `lower`).
func foldedUnits(units []uint16) []uint16 {
	folded := make([]uint16, len(units))
	for i, unit := range units {
		folded[i] = lowerUnit(unit)
	}
	return folded
}

func foldedLists(words []string) [][]uint16 {
	lists := make([][]uint16, len(words))
	for i, word := range words {
		lists[i] = foldedUnits(decodeUTF8(word))
	}
	return lists
}

func (e *engine) newCredentialURI(b *builder, raw json.RawMessage) (scanner, error) {
	var spec credentialSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	rule := &credentialURI{
		search:           b.searcher(spec.Pattern),
		userMin:          spec.UserMin,
		passwordMin:      spec.PasswordMin,
		userContains:     foldedLists(spec.UserIgnoreContains),
		passwordContains: foldedLists(spec.PasswordIgnoreContains),
		passwordEquals:   foldedLists(spec.PasswordIgnoreEquals),
		userEqualsSecret: spec.UserEqualsPassword,
		repeatRun:        spec.RepeatRun,
	}
	for _, source := range spec.VariablePatterns {
		compiled, err := regexp.Compile(b.pattern(source))
		if err != nil {
			return nil, errSpecRejected
		}
		rule.variables = append(rule.variables, compiled)
	}
	return rule, b.err
}

// containsAny: the lower-cased value holds one of the (lower-cased) items.
func containsAny(folded []uint16, items [][]uint16) bool {
	for _, item := range items {
		if indexUnits(folded, item, 0) >= 0 {
			return true
		}
	}
	return false
}

func equalsAny(folded []uint16, items [][]uint16) bool {
	for _, item := range items {
		if equalUnits(folded, item) {
			return true
		}
	}
	return false
}

// isRepeated: at least `runLength` units, all the same unit.
func isRepeated(value []uint16, runLength int) bool {
	if len(value) < runLength {
		return false
	}
	for _, unit := range value {
		if unit != value[0] {
			return false
		}
	}
	return true
}

func (c *credentialURI) isRealUser(user []uint16) bool {
	return len(user) >= c.userMin && !containsAny(foldedUnits(user), c.userContains)
}

// hasVariable is true when a template pattern (`${PASSWORD}`, `%NAME%`) matches anywhere in the password.
func (c *credentialURI) hasVariable(password []uint16) bool {
	if len(c.variables) == 0 {
		return false
	}
	mapped := newText(password).mapped
	for _, variable := range c.variables {
		if variable.MatchString(mapped) {
			return true
		}
	}
	return false
}

func (c *credentialURI) isRealPassword(user []uint16, password []uint16) bool {
	if c.userEqualsSecret && equalUnits(user, password) {
		return false
	}
	if len(password) < c.passwordMin {
		return false
	}
	if c.hasVariable(password) {
		return false
	}
	folded := foldedUnits(password)
	if containsAny(folded, c.passwordContains) {
		return false
	}
	if equalsAny(folded, c.passwordEquals) {
		return false
	}
	return !isRepeated(password, c.repeatRun)
}

// hasBothGroups: the user (group 1) and the password (group 2) took part in the match and are not empty.
func hasBothGroups(loc []int) bool {
	hasUser := loc[2] >= 0 && loc[3] > loc[2]
	hasPassword := loc[4] >= 0 && loc[5] > loc[4]
	return hasUser && hasPassword
}

func (c *credentialURI) scan(t *text) []span {
	var found []span
	for from := 0; ; {
		loc := c.search.find(t, from)
		if loc == nil {
			return found
		}
		from = max(loc[1], loc[0]+1)
		if !hasBothGroups(loc) {
			continue
		}
		user, password := t.units[loc[2]:loc[3]], t.units[loc[4]:loc[5]]
		if c.isRealUser(user) && c.isRealPassword(user, password) {
			found = append(found, span{loc[0], loc[1]})
		}
	}
}
