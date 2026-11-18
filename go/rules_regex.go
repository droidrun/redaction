package redaction

import (
	"encoding/json"
	"strings"
)

// filters are the post-filters of SPEC 4.1 step 3: a candidate that fails one is dropped.
type filters struct {
	requireClass    *unitSet
	requireLiteral  []uint16
	dropPlaceholder bool
	placeholders    *placeholders
}

func (e *engine) newFilters(b *builder, requireClass string, literal string, drop bool) filters {
	found := filters{
		requireLiteral:  decodeUTF8(literal),
		dropPlaceholder: drop,
		placeholders:    e.placeholders,
	}
	if requireClass != "" {
		found.requireClass = b.class(requireClass)
	}
	return found
}

func (f *filters) passes(t *text, candidate span) bool {
	value := t.units[candidate.start:candidate.end]
	if f.requireClass != nil && !f.requireClass.hasAnyIn(value) {
		return false
	}
	if len(f.requireLiteral) > 0 && !containsUnits(value, f.requireLiteral) {
		return false
	}
	return !f.dropPlaceholder || !f.placeholders.isValue(t, candidate.start, candidate.end)
}

type regexSpec struct {
	Pattern         string `json:"pattern"`
	Group           int    `json:"group"`
	NotBefore       string `json:"notBefore"`
	NotAfter        string `json:"notAfter"`
	RequireClass    string `json:"requireClass"`
	RequireLiteral  string `json:"requireLiteral"`
	DropPlaceholder bool   `json:"dropPlaceholder"`
}

// regexRule is SPEC 4.1: one portable pattern, optional neighbour guards and filters.
type regexRule struct {
	search    *searcher
	group     int
	notBefore *unitSet
	notAfter  *unitSet
	filters   filters
}

func (e *engine) newRegexRule(b *builder, raw json.RawMessage) (scanner, error) {
	var spec regexSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	rule := &regexRule{
		search:  b.searcher(spec.Pattern),
		group:   spec.Group,
		filters: e.newFilters(b, spec.RequireClass, spec.RequireLiteral, spec.DropPlaceholder),
	}
	if spec.NotBefore != "" {
		rule.notBefore = b.class(spec.NotBefore)
	}
	if spec.NotAfter != "" {
		rule.notAfter = b.class(spec.NotAfter)
	}
	return rule, b.err
}

// refuses is true when a unit next to the match is in a guard class.
func (r *regexRule) refuses(units []uint16, match span) bool {
	if r.notBefore != nil && match.start > 0 && r.notBefore.has(units[match.start-1]) {
		return true
	}
	return r.notAfter != nil && match.end < len(units) && r.notAfter.has(units[match.end])
}

func (r *regexRule) candidate(loc []int) (span, bool) {
	if r.group == 0 {
		return span{loc[0], loc[1]}, true
	}
	start, end := loc[2*r.group], loc[2*r.group+1]
	return span{start, end}, start >= 0
}

func (r *regexRule) scan(t *text) []span {
	var found []span
	for from := 0; ; {
		loc := r.search.find(t, from)
		if loc == nil {
			return found
		}
		match := span{loc[0], loc[1]}
		if r.refuses(t.units, match) {
			from = match.start + 1
			continue
		}
		from = max(match.end, match.start+1)
		candidate, taken := r.candidate(loc)
		if taken && r.filters.passes(t, candidate) {
			found = append(found, candidate)
		}
	}
}

type dottedSpec struct {
	Lead         string `json:"lead"`
	Separator    string `json:"separator"`
	SegmentClass string `json:"segmentClass"`
	WordClass    string `json:"wordClass"`
	MinSegment   int    `json:"minSegment"`
	Segments     int    `json:"segments"`
}

// dottedToken is SPEC 4.2: the JSON Web Token shape, in linear time.
type dottedToken struct {
	lead       []uint16
	separator  uint16
	segment    *unitSet
	word       *unitSet
	minSegment int
	segments   int
}

func (e *engine) newDottedToken(b *builder, raw json.RawMessage) (scanner, error) {
	var spec dottedSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &dottedToken{
		lead:       decodeUTF8(spec.Lead),
		separator:  decodeUTF8(spec.Separator)[0],
		segment:    b.class(spec.SegmentClass),
		word:       b.class(spec.WordClass),
		minSegment: spec.MinSegment,
		segments:   spec.Segments,
	}, b.err
}

func (d *dottedToken) isWordAt(units []uint16, at int) bool {
	return at >= 0 && at < len(units) && d.word.has(units[at])
}

func (d *dottedToken) isBoundary(units []uint16, at int) bool {
	return d.isWordAt(units, at-1) != d.isWordAt(units, at)
}

// lastSegmentEnd is the end of the longest last segment that ends on a word boundary, or -1.
func (d *dottedToken) lastSegmentEnd(units []uint16, from int, length int) int {
	for take := length; take >= d.minSegment; take-- {
		if d.isBoundary(units, from+take) {
			return from + take
		}
	}
	return -1
}

// match tries one start. It returns the match end, or -1 and the end of the first segment's run.
func (d *dottedToken) match(units []uint16, start int) (int, int) {
	position := start + len(d.lead)
	firstRunEnd := position
	for segment := 0; segment < d.segments; segment++ {
		end := runEnd(units, position, d.segment, unbounded)
		if segment == 0 {
			firstRunEnd = end
		}
		length := end - position
		if length < d.minSegment {
			return -1, firstRunEnd
		}
		if segment == d.segments-1 {
			return d.lastSegmentEnd(units, position, length), firstRunEnd
		}
		if end >= len(units) || units[end] != d.separator {
			return -1, firstRunEnd
		}
		position = end + 1
	}
	return -1, firstRunEnd
}

func (d *dottedToken) scan(t *text) []span {
	var found []span
	from := 0
	skipUntil := 0
	for {
		start := indexUnits(t.units, d.lead, from)
		if start < 0 {
			return found
		}
		from = start + 1
		if start < skipUntil || !d.isBoundary(t.units, start) {
			continue
		}
		end, firstRunEnd := d.match(t.units, start)
		if end < 0 {
			skipUntil = firstRunEnd
			continue
		}
		found = append(found, span{start, end})
		from = end
	}
}

type pemSpec struct {
	Header       string `json:"header"`
	Footer       string `json:"footer"`
	FooterMarker string `json:"footerMarker"`
	BodyChar     string `json:"bodyChar"`
	BodyLimit    int    `json:"bodyLimit"`
}

// pemBlocks is SPEC 4.3: a header through its footer, or through its body-looking run.
type pemBlocks struct {
	header    *searcher
	footer    *anchored
	marker    string
	body      *unitSet
	bodyLimit int
}

func (e *engine) newPemBlocks(b *builder, raw json.RawMessage) (scanner, error) {
	var spec pemSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &pemBlocks{
		header:    b.searcher(spec.Header),
		footer:    b.anchored(spec.Footer),
		marker:    textFromString(spec.FooterMarker).mapped,
		body:      b.class(spec.BodyChar),
		bodyLimit: spec.BodyLimit,
	}, b.err
}

// markerFinder finds the footer marker; headers come in increasing order, so one result serves
// every later search that starts before it.
type markerFinder struct {
	t      *text
	marker string
	from   int
	found  int
	primed bool
}

func (m *markerFinder) indexFrom(from int) int {
	if m.primed && from >= m.from && (m.found == -1 || m.found >= from) {
		return m.found
	}
	m.primed = true
	m.from = from
	m.found = -1
	at := strings.Index(m.t.mapped[m.t.byteAt(from):], m.marker)
	if at >= 0 {
		m.found = m.t.unitAt(m.t.byteAt(from) + at)
	}
	return m.found
}

func (p *pemBlocks) scan(t *text) []span {
	var found []span
	finder := &markerFinder{t: t, marker: p.marker}
	covered := 0
	for from := 0; ; {
		loc := p.header.find(t, from)
		if loc == nil {
			return found
		}
		from = loc[1]
		if loc[0] < covered {
			continue
		}
		bodyEnd := runEnd(t.units, loc[1], p.body, min(p.bodyLimit, len(t.units)-loc[1]))
		covered = bodyEnd
		marker := finder.indexFrom(loc[1])
		if marker >= 0 && marker < bodyEnd {
			if end := p.footer.end(t, marker); end >= 0 {
				covered = end
			}
		}
		found = append(found, span{loc[0], covered})
	}
}

type cookieSpec struct {
	Prefix          string `json:"prefix"`
	PlainChar       string `json:"plainChar"`
	EscapeStop      string `json:"escapeStop"`
	RequireLiteral  string `json:"requireLiteral"`
	DropPlaceholder bool   `json:"dropPlaceholder"`
}

// cookieLines is SPEC 4.4: `Cookie: a=b; c=d` up to the end of the line.
type cookieLines struct {
	search  *searcher
	run     runClasses
	filters filters
}

func (e *engine) newCookieLines(b *builder, raw json.RawMessage) (scanner, error) {
	var spec cookieSpec
	if err := decodeRule(raw, &spec); err != nil {
		return nil, err
	}
	return &cookieLines{
		search:  b.searcher(spec.Prefix),
		run:     runClasses{plain: b.class(spec.PlainChar), stop: b.class(spec.EscapeStop)},
		filters: e.newFilters(b, "", spec.RequireLiteral, spec.DropPlaceholder),
	}, b.err
}

func (c *cookieLines) scan(t *text) []span {
	var found []span
	for from := 0; ; {
		loc := c.search.find(t, from)
		if loc == nil {
			return found
		}
		value := span{loc[1], guardedRunEnd(t.units, loc[1], c.run, unbounded)}
		if value.end == value.start {
			from = loc[0] + 1
			continue
		}
		from = value.end
		if c.filters.passes(t, value) {
			found = append(found, value)
		}
	}
}
