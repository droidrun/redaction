package redaction

import (
	"errors"
	"sort"
	"unicode/utf8"
)

type kind uint8

const (
	kindNull kind = iota
	kindBool
	kindNumber
	kindString
	kindArray
	kindObject
)

// node is a JSON value. Strings are UTF-16 units (a lone surrogate survives); objects keep their
// members in the contract order of SPEC section 8.
//
// The parser stops building at the limits of the call (see parseLimits). A container that was cut
// short has cut set (and, for an object, left: the key of the first entry that was left out);
// a string that is longer than the character limit has no units and its size in strSize.
type node struct {
	kind    kind
	flag    bool
	raw     []byte
	str     []uint16
	strSize int
	items   []*node
	members []member
	cut     bool
	left    *leftOut
}

// leftOut is what an object remembers of its entries that were left out under a limit. It sits behind a
// pointer because every node of a large input carries the field. `first` is the key of the first entry
// left out; `keys` are the keys of the entries left out that hold the text `[REDACTED`: the walk
// reserves them like the keys it visits (SPEC 8). They are kept up to the character limit of the call;
// further ones are not (the walk then only avoids a duplicate key).
type leftOut struct {
	first []uint16
	keys  [][]uint16
}

// firstLeftOut is the key of the first entry that was left out (nil when there is none).
func (n *node) firstLeftOut() []uint16 {
	if n.left == nil {
		return nil
	}
	return n.left.first
}

type member struct {
	key []uint16
	val *node
}

// ErrInvalidJSON is returned for input that is not one JSON value. It never quotes the input.
var ErrInvalidJSON = errors.New("redaction: input is not valid JSON")

func (n *node) isPrimitive() bool {
	return n.kind != kindArray && n.kind != kindObject
}

// strLen is the length in units of a string node, also one whose units were not kept.
func (n *node) strLen() int {
	if n.strSize > 0 {
		return n.strSize
	}
	return len(n.str)
}

// parseLimits bound what the parser builds, so memory stays proportional to the limits and not to
// the input: past the node budget the rest is only checked for syntax (the walk would cut it
// anyway) and a container deeper than depth is checked but not built. With elideStrings (strict)
// the units of all strings and keys are charged against `chars` in document order, and a string
// that does not fit is counted but not kept; the walk then cuts it, as it does a string that
// does not fit its own budget. Keys are always kept. What the walk would visit is built as is.
type parseLimits struct {
	nodes        int
	depth        int
	chars        int
	elideStrings bool
}

// parser reads one JSON value iteratively, so nesting depth costs no stack.
type parser struct {
	data   []byte
	at     int
	limits parseLimits
	// reserveRoom is what is left of the units that may be kept for node.left.
	reserveRoom int
}

type openContainer struct {
	node *node
	key  []uint16
}

func (p *parser) skipSpace() {
	for p.at < len(p.data) {
		switch p.data[p.at] {
		case ' ', '\t', '\n', '\r':
			p.at++
		default:
			return
		}
	}
}

func (p *parser) peek() (byte, bool) {
	if p.at >= len(p.data) {
		return 0, false
	}
	return p.data[p.at], true
}

func (p *parser) take(c byte) bool {
	if next, ok := p.peek(); ok && next == c {
		p.at++
		return true
	}
	return false
}

func (p *parser) literal(word string) error {
	if p.at+len(word) > len(p.data) || string(p.data[p.at:p.at+len(word)]) != word {
		return ErrInvalidJSON
	}
	p.at += len(word)
	return nil
}

func (p *parser) unicodeEscape() (uint16, error) {
	if p.at+4 > len(p.data) {
		return 0, ErrInvalidJSON
	}
	var unit uint16
	for i := 0; i < 4; i++ {
		digit, ok := hexDigit(uint16(p.data[p.at+i]))
		if !ok {
			return 0, ErrInvalidJSON
		}
		unit = unit<<4 | uint16(digit)
	}
	p.at += 4
	return unit, nil
}

var simpleEscapes = map[byte]uint16{
	'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t',
}

func (p *parser) escape() (uint16, error) {
	c, ok := p.peek()
	if !ok {
		return 0, ErrInvalidJSON
	}
	p.at++
	if c == 'u' {
		return p.unicodeEscape()
	}
	unit, known := simpleEscapes[c]
	if !known {
		return 0, ErrInvalidJSON
	}
	return unit, nil
}

// unitBuffer collects the units of a string, up to `keep` of them; it counts every unit.
type unitBuffer struct {
	units []uint16
	count int
	keep  int
}

func (b *unitBuffer) add(unit uint16) {
	b.count++
	if b.count <= b.keep {
		b.units = append(b.units, unit)
		return
	}
	b.units = nil
}

// str reads a string after its opening quote. It keeps at most `keep` units (a negative keep
// keeps none) and returns the number of units the string has.
func (p *parser) str(keep int) ([]uint16, int, error) {
	buffer := unitBuffer{keep: keep}
	for p.at < len(p.data) {
		c := p.data[p.at]
		switch {
		case c == '"':
			p.at++
			return buffer.units, buffer.count, nil
		case c < 0x20:
			return nil, 0, ErrInvalidJSON
		case c == '\\':
			p.at++
			unit, err := p.escape()
			if err != nil {
				return nil, 0, err
			}
			buffer.add(unit)
		case c < utf8.RuneSelf:
			buffer.add(uint16(c))
			p.at++
		default:
			r, size := utf8.DecodeRune(p.data[p.at:])
			p.at += size
			if r < 0x10000 {
				buffer.add(uint16(r))
				continue
			}
			r -= 0x10000
			buffer.add(uint16(0xD800 + (r >> 10)))
			buffer.add(uint16(0xDC00 + (r & 0x3FF)))
		}
	}
	return nil, 0, ErrInvalidJSON
}

func isDigitByte(c byte) bool {
	return c >= '0' && c <= '9'
}

func (p *parser) digits() bool {
	start := p.at
	for p.at < len(p.data) && isDigitByte(p.data[p.at]) {
		p.at++
	}
	return p.at > start
}

func (p *parser) fraction() bool {
	if !p.take('.') {
		return true
	}
	return p.digits()
}

func (p *parser) exponent() bool {
	if !p.take('e') && !p.take('E') {
		return true
	}
	if !p.take('+') {
		p.take('-')
	}
	return p.digits()
}

// numberToken reads the JSON number grammar and returns its text.
func (p *parser) numberToken() ([]byte, error) {
	start := p.at
	p.take('-')
	if !p.take('0') && !p.digits() {
		return nil, ErrInvalidJSON
	}
	if !p.fraction() || !p.exponent() {
		return nil, ErrInvalidJSON
	}
	return p.data[start:p.at], nil
}

// number reads a number and keeps its text: a number that is not replaced is written back exactly
// as it appeared (it is a slice of the input, valid until the call returns).
func (p *parser) number() (*node, error) {
	token, err := p.numberToken()
	if err != nil {
		return nil, err
	}
	return &node{kind: kindNumber, raw: token}, nil
}

// charge takes units off the character budget (strict only; the budget does not go below zero).
func (p *parser) charge(units int) {
	if p.limits.elideStrings {
		p.limits.chars = max(0, p.limits.chars-units)
	}
}

func (p *parser) stringNode() (*node, error) {
	keep := unbounded
	if p.limits.elideStrings {
		keep = p.limits.chars
	}
	units, count, err := p.str(keep)
	if err != nil {
		return nil, err
	}
	if units == nil && count > 0 {
		p.limits.chars = 0
		return &node{kind: kindString, strSize: count}, nil
	}
	p.charge(count)
	return &node{kind: kindString, str: units}, nil
}

// scalar reads a value that is not a container.
func (p *parser) scalar() (*node, error) {
	c, ok := p.peek()
	if !ok {
		return nil, ErrInvalidJSON
	}
	switch {
	case c == '"':
		p.at++
		return p.stringNode()
	case c == 't':
		return &node{kind: kindBool, flag: true}, p.literal("true")
	case c == 'f':
		return &node{kind: kindBool}, p.literal("false")
	case c == 'n':
		return &node{kind: kindNull}, p.literal("null")
	case c == '-' || isDigitByte(c):
		return p.number()
	}
	return nil, ErrInvalidJSON
}

// skipScalar checks a scalar without building it.
func (p *parser) skipScalar() error {
	c, ok := p.peek()
	if !ok {
		return ErrInvalidJSON
	}
	switch {
	case c == '"':
		p.at++
		_, _, err := p.str(-1)
		return err
	case c == 't':
		return p.literal("true")
	case c == 'f':
		return p.literal("false")
	case c == 'n':
		return p.literal("null")
	case c == '-' || isDigitByte(c):
		_, err := p.numberToken()
		return err
	}
	return ErrInvalidJSON
}

// bitStack is a stack of booleans, one bit each: the kind of every open container while a value
// is only checked.
type bitStack struct {
	words []uint64
	size  int
}

func (s *bitStack) push(isObject bool) {
	if s.size%64 == 0 {
		s.words = append(s.words, 0)
	}
	if isObject {
		s.words[s.size/64] |= 1 << (s.size % 64)
	} else {
		s.words[s.size/64] &^= 1 << (s.size % 64)
	}
	s.size++
}

func (s *bitStack) top() bool {
	return s.words[(s.size-1)/64]&(1<<((s.size-1)%64)) != 0
}

func (s *bitStack) pop() {
	s.size--
	if s.size%64 == 0 {
		s.words = s.words[:s.size/64]
	}
}

func closerFor(isObject bool) byte {
	if isObject {
		return '}'
	}
	return ']'
}

// skipKey reads `"key":` without keeping the key.
func (p *parser) skipKey() error {
	p.skipSpace()
	if !p.take('"') {
		return ErrInvalidJSON
	}
	if _, _, err := p.str(-1); err != nil {
		return err
	}
	p.skipSpace()
	if !p.take(':') {
		return ErrInvalidJSON
	}
	return nil
}

// skipOpen reads a value; for a container with entries it reads the first key and reports that the
// container is now open.
func (p *parser) skipOpen(open *bitStack) error {
	p.skipSpace()
	c, ok := p.peek()
	if !ok {
		return ErrInvalidJSON
	}
	if c != '[' && c != '{' {
		return p.skipScalar()
	}
	p.at++
	p.skipSpace()
	isObject := c == '{'
	if p.take(closerFor(isObject)) {
		return nil
	}
	open.push(isObject)
	if isObject {
		return p.skipKey()
	}
	return nil
}

// skipValue checks one value for syntax and builds nothing; memory is one bit per nesting level.
func (p *parser) skipValue() error {
	var open bitStack
	for {
		before := open.size
		if err := p.skipOpen(&open); err != nil {
			return err
		}
		if open.size > before {
			continue
		}
		for {
			if open.size == 0 {
				return nil
			}
			isObject := open.top()
			p.skipSpace()
			if p.take(closerFor(isObject)) {
				open.pop()
				continue
			}
			if !p.take(',') {
				return ErrInvalidJSON
			}
			if isObject {
				if err := p.skipKey(); err != nil {
					return err
				}
			}
			break
		}
	}
}

// parseJSON reads exactly one JSON value (RFC 8259 grammar, as ECMAScript JSON.parse reads it).
func parseJSON(data []byte, limits parseLimits) (*node, error) {
	p := &parser{data: data, limits: limits, reserveRoom: limits.chars}
	var stack []*openContainer
	for {
		p.skipSpace()
		value, container, err := p.value(len(stack))
		if err != nil {
			return nil, err
		}
		if container != nil {
			stack = append(stack, container)
			continue
		}
		var more bool
		stack, value, more, err = p.unwind(stack, value)
		if err != nil {
			return nil, err
		}
		if !more {
			return p.finish(value)
		}
	}
}

// unwind attaches a finished value to the open containers, closing every one that ends. It
// returns more=true when the next value of an open container is to be read. A nil value is one
// that was left out; its container is marked cut.
func (p *parser) unwind(stack []*openContainer, value *node) ([]*openContainer, *node, bool, error) {
	for len(stack) > 0 {
		next, done, err := p.closeOrContinue(stack, value)
		if err != nil {
			return stack, nil, false, err
		}
		if !done {
			return stack, nil, true, nil
		}
		stack = stack[:len(stack)-1]
		value = next
	}
	return stack, value, false, nil
}

func (p *parser) finish(value *node) (*node, error) {
	p.skipSpace()
	if p.at != len(p.data) {
		return nil, ErrInvalidJSON
	}
	if value == nil {
		return &node{kind: kindNull}, nil
	}
	return value, nil
}

// value reads a scalar, or opens a container (and reads its first key). A container that closes
// at once is returned as a finished value. When the node budget is spent the value is checked
// and left out: the result is nil. A container at or below the depth limit is checked and kept
// empty (the walk cuts it before it looks inside).
func (p *parser) value(depth int) (*node, *openContainer, error) {
	c, ok := p.peek()
	if !ok {
		return nil, nil, ErrInvalidJSON
	}
	if p.limits.nodes <= 0 {
		return nil, nil, p.skipValue()
	}
	p.limits.nodes--
	if c != '[' && c != '{' {
		value, err := p.scalar()
		return value, nil, err
	}
	if depth >= p.limits.depth {
		kept := &node{kind: kindArray}
		if c == '{' {
			kept.kind = kindObject
		}
		return kept, nil, p.skipValue()
	}
	p.at++
	p.skipSpace()
	if c == '[' {
		if p.take(']') {
			return &node{kind: kindArray}, nil, nil
		}
		return nil, &openContainer{node: &node{kind: kindArray}}, nil
	}
	if p.take('}') {
		return &node{kind: kindObject}, nil, nil
	}
	open := &openContainer{node: &node{kind: kindObject}}
	return nil, open, p.memberKey(open)
}

func (p *parser) memberKey(open *openContainer) error {
	p.skipSpace()
	if !p.take('"') {
		return ErrInvalidJSON
	}
	key, count, err := p.str(unbounded)
	if err != nil {
		return err
	}
	p.skipSpace()
	if !p.take(':') {
		return ErrInvalidJSON
	}
	p.charge(count)
	open.key = key
	return nil
}

// closeOrContinue attaches `value` to the open container on top. It returns done=true with the
// finished container when the container ends, or done=false after reading the next key.
func (p *parser) closeOrContinue(stack []*openContainer, value *node) (*node, bool, error) {
	top := stack[len(stack)-1]
	isObject := top.node.kind == kindObject
	p.attach(top, value)
	p.skipSpace()
	if p.take(closerFor(isObject)) {
		finishObject(top.node)
		return top.node, true, nil
	}
	if !p.take(',') {
		return nil, false, ErrInvalidJSON
	}
	if isObject {
		return nil, false, p.memberKey(top)
	}
	return nil, false, nil
}

// keepCutKey remembers the key of an entry that was left out: the first one, and every one that holds
// a placeholder (as long as there is room).
func (p *parser) keepCutKey(top *openContainer) {
	if top.node.left == nil {
		top.node.left = &leftOut{first: top.key}
	}
	holdsPlaceholder := containsUnits(top.key, redactedOpen)
	if holdsPlaceholder && len(top.key) <= p.reserveRoom {
		top.node.left.keys = append(top.node.left.keys, top.key)
		p.reserveRoom -= len(top.key)
	}
}

// attach adds a finished value to its container; a value that was left out marks the container
// cut (an object remembers the key of the first entry that was left out).
func (p *parser) attach(top *openContainer, value *node) {
	switch {
	case value == nil:
		if top.node.kind == kindObject {
			p.keepCutKey(top)
		}
		top.node.cut = true
	case top.node.kind == kindObject:
		top.node.members = append(top.node.members, member{key: top.key, val: value})
	default:
		top.node.items = append(top.node.items, value)
	}
}

// finishObject applies the duplicate-key rule (last value wins, first position stays) and the
// ECMAScript key order (integer-like keys ascending, then insertion order).
func finishObject(object *node) {
	if object.kind == kindObject {
		object.members = orderMembers(dedupeMembers(object.members))
	}
}

func unitsKey(units []uint16) string {
	raw := make([]byte, 0, 2*len(units))
	for _, unit := range units {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	return string(raw)
}

func dedupeMembers(members []member) []member {
	if len(members) < 2 {
		return members
	}
	position := make(map[string]int, len(members))
	unique := make([]member, 0, len(members))
	for _, entry := range members {
		key := unitsKey(entry.key)
		at, seen := position[key]
		if seen {
			unique[at].val = entry.val
			continue
		}
		position[key] = len(unique)
		unique = append(unique, entry)
	}
	return unique
}

const maxArrayIndex = 4294967294

// arrayIndex reports whether key is a canonical array index (no sign, no leading zero).
func arrayIndex(key []uint16) (uint64, bool) {
	if len(key) == 0 || len(key) > 10 || (key[0] == '0' && len(key) > 1) {
		return 0, false
	}
	var value uint64
	for _, unit := range key {
		if unit < '0' || unit > '9' {
			return 0, false
		}
		value = value*10 + uint64(unit-'0')
	}
	return value, value <= maxArrayIndex
}

func orderMembers(members []member) []member {
	var indexed []member
	var named []member
	for _, entry := range members {
		if _, isIndex := arrayIndex(entry.key); isIndex {
			indexed = append(indexed, entry)
		} else {
			named = append(named, entry)
		}
	}
	if len(indexed) == 0 {
		return members
	}
	sort.SliceStable(indexed, func(i, j int) bool {
		left, _ := arrayIndex(indexed[i].key)
		right, _ := arrayIndex(indexed[j].key)
		return left < right
	})
	return append(indexed, named...)
}
