package redaction

import (
	"errors"
	"sort"
	"strconv"
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
type node struct {
	kind    kind
	flag    bool
	num     float64
	str     []uint16
	items   []*node
	members []member
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

// parser reads one JSON value iteratively, so nesting depth costs no stack.
type parser struct {
	data []byte
	at   int
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

func (p *parser) literal(word string, value *node) (*node, error) {
	if p.at+len(word) > len(p.data) || string(p.data[p.at:p.at+len(word)]) != word {
		return nil, ErrInvalidJSON
	}
	p.at += len(word)
	return value, nil
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

// str reads a string after its opening quote.
func (p *parser) str() ([]uint16, error) {
	var units []uint16
	for p.at < len(p.data) {
		c := p.data[p.at]
		switch {
		case c == '"':
			p.at++
			return units, nil
		case c < 0x20:
			return nil, ErrInvalidJSON
		case c == '\\':
			p.at++
			unit, err := p.escape()
			if err != nil {
				return nil, err
			}
			units = append(units, unit)
		case c < utf8.RuneSelf:
			units = append(units, uint16(c))
			p.at++
		default:
			r, size := utf8.DecodeRune(p.data[p.at:])
			units = appendRune(units, r)
			p.at += size
		}
	}
	return nil, ErrInvalidJSON
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

// number reads the JSON number grammar and converts it to the nearest double.
func (p *parser) number() (*node, error) {
	start := p.at
	p.take('-')
	if !p.take('0') && !p.digits() {
		return nil, ErrInvalidJSON
	}
	if !p.fraction() || !p.exponent() {
		return nil, ErrInvalidJSON
	}
	value, err := strconv.ParseFloat(string(p.data[start:p.at]), 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, ErrInvalidJSON
	}
	return &node{kind: kindNumber, num: value}, nil
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
		units, err := p.str()
		return &node{kind: kindString, str: units}, err
	case c == 't':
		return p.literal("true", &node{kind: kindBool, flag: true})
	case c == 'f':
		return p.literal("false", &node{kind: kindBool})
	case c == 'n':
		return p.literal("null", &node{kind: kindNull})
	case c == '-' || isDigitByte(c):
		return p.number()
	}
	return nil, ErrInvalidJSON
}

// parseJSON reads exactly one JSON value (RFC 8259 grammar, as ECMAScript JSON.parse reads it).
func parseJSON(data []byte) (*node, error) {
	p := &parser{data: data}
	var stack []*openContainer
	for {
		p.skipSpace()
		value, container, err := p.value()
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
// returns more=true when the next value of an open container is to be read.
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
	return value, nil
}

// value reads a scalar, or opens a container (and reads its first key). A container that closes
// at once is returned as a finished value.
func (p *parser) value() (*node, *openContainer, error) {
	c, ok := p.peek()
	if !ok {
		return nil, nil, ErrInvalidJSON
	}
	if c != '[' && c != '{' {
		value, err := p.scalar()
		return value, nil, err
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
	key, err := p.str()
	if err != nil {
		return err
	}
	p.skipSpace()
	if !p.take(':') {
		return ErrInvalidJSON
	}
	open.key = key
	return nil
}

// closeOrContinue attaches `value` to the open container on top. It returns done=true with the
// finished container when the container ends, or done=false after reading the next key.
func (p *parser) closeOrContinue(stack []*openContainer, value *node) (*node, bool, error) {
	top := stack[len(stack)-1]
	isObject := top.node.kind == kindObject
	if isObject {
		top.node.members = append(top.node.members, member{key: top.key, val: value})
	} else {
		top.node.items = append(top.node.items, value)
	}
	p.skipSpace()
	closer := byte(']')
	if isObject {
		closer = '}'
	}
	if p.take(closer) {
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
