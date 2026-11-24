package redaction

import "encoding/json"

// strictEdit is one entry of `rules.json` `strict` (SPEC 4.10): it matches the entries of the rule list
// by `id` and/or `kind` and either sets fields of them (`set`) or adds a rule right after the one it matches
// (`add`).
type strictEdit struct {
	ID   string                     `json:"id"`
	Kind string                     `json:"kind"`
	Set  map[string]json.RawMessage `json:"set"`
	Add  json.RawMessage            `json:"add"`
}

func (edit strictEdit) matches(head ruleHead) bool {
	hasID := edit.ID == "" || head.ID == edit.ID
	hasKind := edit.Kind == "" || head.Kind == edit.Kind
	return hasID && hasKind
}

// withFields is the rule with the fields of `set` replacing its own.
func withFields(raw json.RawMessage, set map[string]json.RawMessage) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := decodeRule(raw, &fields); err != nil {
		return nil, err
	}
	for name, value := range set {
		fields[name] = value
	}
	edited, err := json.Marshal(fields)
	if err != nil {
		return nil, errSpecRejected
	}
	return edited, nil
}

func (edit strictEdit) apply(rules []json.RawMessage) ([]json.RawMessage, error) {
	var targets []int
	for at, raw := range rules {
		var head ruleHead
		if err := decodeRule(raw, &head); err != nil {
			return nil, err
		}
		if edit.matches(head) {
			targets = append(targets, at)
		}
	}
	if len(targets) == 0 {
		return nil, errSpecRejected
	}
	if edit.Add != nil {
		if len(targets) != 1 {
			return nil, errSpecRejected
		}
		after := targets[0] + 1
		added := append([]json.RawMessage(nil), rules[:after]...)
		return append(append(added, edit.Add), rules[after:]...), nil
	}
	edited := append([]json.RawMessage(nil), rules...)
	for _, at := range targets {
		var err error
		if edited[at], err = withFields(rules[at], edit.Set); err != nil {
			return nil, err
		}
	}
	return edited, nil
}

// strictRules is the rule list of `strict` (SPEC 4.10): `pipeline` with the edits applied in order.
func strictRules(pipeline []json.RawMessage, edits []strictEdit) ([]json.RawMessage, error) {
	rules := pipeline
	for _, edit := range edits {
		var err error
		if rules, err = edit.apply(rules); err != nil {
			return nil, err
		}
	}
	return rules, nil
}
