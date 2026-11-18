package redaction

import "encoding/json"

type pemKeySpec struct {
	Header       string   `json:"header"`
	Footer       string   `json:"footer"`
	BodyClass    string   `json:"bodyClass"`
	MinBody      int      `json:"minBody"`
	MaxBody      int      `json:"maxBody"`
	Newline      string   `json:"newline"`
	StripClass   string   `json:"stripClass"`
	StripLiteral string   `json:"stripLiteral"`
	ContentClass string   `json:"contentClass"`
	PadChar      string   `json:"padChar"`
	MinContent   int      `json:"minContent"`
	Magic        []string `json:"magic"`
}

// pemKey is SPEC 4.14: the private key rule of the preset. Unlike pem-blocks, an unterminated or
// invalid block is not a hit.
type pemKey struct {
	header       *searcher
	footer       *anchored
	body         *unitSet
	minBody      int
	maxBody      int
	newline      uint16
	strip        *unitSet
	stripLiteral []uint16
	content      *unitSet
	pad          *unitSet
	minContent   int
	magic        [][]uint16
}

func (e *engine) newPemKey(b *builder, raw json.RawMessage) (scanner, error) {
	var spec pemKeySpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &pemKey{
		header:       b.searcher(spec.Header),
		footer:       b.anchored(spec.Footer),
		body:         b.class(spec.BodyClass),
		minBody:      spec.MinBody,
		maxBody:      spec.MaxBody,
		newline:      decodeUTF8(spec.Newline)[0],
		strip:        b.class(spec.StripClass),
		stripLiteral: decodeUTF8(spec.StripLiteral),
		content:      b.class(spec.ContentClass),
		pad:          b.class(spec.PadChar),
		minContent:   spec.MinContent,
		magic:        asUnitLists(spec.Magic),
	}, b.err
}

// hasBodyLength: a body of `length` units can be chosen, with or without the line feed after the
// header (`leading`) and before the footer (`trailing`), within the bounds.
func (p *pemKey) hasBodyLength(length int, leading bool, trailing bool) bool {
	options := []int{length}
	if leading {
		options = append(options, length-1)
	}
	if trailing {
		options = append(options, length-1)
	}
	if leading && trailing && length >= 2 {
		options = append(options, length-2)
	}
	for _, option := range options {
		if option >= p.minBody && option <= p.maxBody {
			return true
		}
	}
	return false
}

// stripped is the body without whitespace and without the two-unit text `\n`.
func (p *pemKey) stripped(body []uint16) []uint16 {
	kept := make([]uint16, 0, len(body))
	for at := 0; at < len(body); at++ {
		if p.strip.has(body[at]) {
			continue
		}
		if hasUnitsAt(body, p.stripLiteral, at) {
			at += len(p.stripLiteral) - 1
			continue
		}
		kept = append(kept, body[at])
	}
	return kept
}

// isKeyContent: one or more content units, then only pad units, long enough, starting with a magic prefix.
func (p *pemKey) isKeyContent(content []uint16) bool {
	contentEnd := runEnd(content, 0, p.content, unbounded)
	if contentEnd == 0 {
		return false
	}
	if runEnd(content, contentEnd, p.pad, unbounded) != len(content) {
		return false
	}
	if len(content) < p.minContent {
		return false
	}
	for _, prefix := range p.magic {
		if hasUnitsAt(content, prefix, 0) {
			return true
		}
	}
	return false
}

func (p *pemKey) scan(t *text) []span {
	var memo runMemo
	var found []span
	for from := 0; ; {
		loc := p.header.find(t, from)
		if loc == nil {
			return found
		}
		start, bodyStart := loc[0], loc[1]
		from = start + 1
		bodyEnd := memo.end(t.units, p.body, bodyStart)
		length := bodyEnd - bodyStart
		leading := bodyStart < len(t.units) && t.units[bodyStart] == p.newline
		trailing := length > 0 && t.units[bodyEnd-1] == p.newline
		if !p.hasBodyLength(length, leading, trailing) {
			continue
		}
		end := p.footer.end(t, bodyEnd)
		if end < 0 || !p.isKeyContent(p.stripped(t.units[bodyStart:bodyEnd])) {
			continue
		}
		found = append(found, span{start, end})
		from = end
	}
}
