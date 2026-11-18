package redaction

// walker is the iterative JSON walk of SPEC 9.2 (compat) and 9.3 (strict). It never recurses, so
// deep input costs no stack.
type walker struct {
	e        *engine
	mode     scanMode
	strict   bool
	nodes    int
	chars    int
	maxDepth int
	skip     [][]uint16
	rec      *recorder
}

type frame struct {
	src     *node
	idx     int
	out     *node
	verdict Verdict
	depth   int
	outKey  []uint16
	index   map[string]int
	cutDone bool
	// lastNumber is, per output key that was taken, the number of the last numbered key made of it.
	lastNumber map[string]int
}

// indexAbove is the member count from which an output object keeps a key map.
const indexAbove = 8

func (f *frame) isArray() bool {
	return f.src.kind == kindArray
}

func (f *frame) done() bool {
	return f.idx >= entryCount(f.src)
}

// addMember appends an entry to the output object.
func (f *frame) addMember(key []uint16, value *node) {
	f.out.members = append(f.out.members, member{key: key, val: value})
	if f.index != nil {
		f.index[unitsKey(key)] = len(f.out.members) - 1
	}
}

// place stores a finished value under the current output key of the frame (or appends it to an
// array). When an earlier entry already has that output key (two keys were redacted to the same
// placeholder), no value is lost: the first keeps the key, each further one gets a number inside the
// brackets of the placeholder, `[REDACTED:rule#2]`, `#3`, ... in contract order.
func (w *walker) place(f *frame, value *node) {
	if f.isArray() {
		f.out.items = append(f.out.items, value)
		return
	}
	at := f.memberAt(f.outKey)
	if at < 0 {
		f.addMember(f.outKey, value)
		return
	}
	if key, numbered := w.numberedKey(f, f.outKey); numbered {
		f.addMember(key, value)
		return
	}
	f.out.members[at].val = value // a key without a placeholder cannot collide; kept as the old rule
}

// numberedKey is the next free numbered form of a taken output key.
func (w *walker) numberedKey(f *frame, key []uint16) ([]uint16, bool) {
	if f.lastNumber == nil {
		f.lastNumber = make(map[string]int)
	}
	base := unitsKey(key)
	last := max(f.lastNumber[base], 1)
	for {
		last++
		candidate, ok := w.e.placeholders.numbered(key, last)
		if !ok {
			return nil, false
		}
		if f.memberAt(candidate) < 0 {
			f.lastNumber[base] = last
			return candidate, true
		}
	}
}

func (f *frame) memberAt(key []uint16) int {
	if f.index == nil && len(f.out.members) > indexAbove {
		f.index = make(map[string]int, len(f.out.members)*2)
		for at, entry := range f.out.members {
			f.index[unitsKey(entry.key)] = at
		}
	}
	if f.index != nil {
		if at, found := f.index[unitsKey(key)]; found {
			return at
		}
		return -1
	}
	for at, entry := range f.out.members {
		if equalUnits(entry.key, key) {
			return at
		}
	}
	return -1
}

func stringNode(units []uint16) *node {
	return &node{kind: kindString, str: units}
}

// limit is a placeholder for what was not scanned, with its hit.
func (w *walker) limit(ruleID string) *node {
	w.rec.add(ruleID)
	return stringNode(w.e.placeholders.readUnits(ruleID))
}

// leafReplacement is SPEC 6 `leafPlaceholder`: the key-context placeholder, or nil to keep.
func (w *walker) leafReplacement(v Verdict, value *node) *node {
	if v == VerdictNone {
		return nil
	}
	switch value.kind {
	case kindString:
		if value.strLen() == 0 || w.e.placeholders.isWhole(value.str) {
			return nil
		}
	case kindNumber:
		if v != VerdictAny {
			return nil
		}
	default:
		return nil
	}
	id := w.e.spec.algorithms.RuleIDs.KeyContext
	w.rec.add(id)
	return stringNode(w.e.placeholders.readUnits(id))
}

func (w *walker) scanLeaf(value *node, v Verdict) *node {
	length := value.strLen()
	if length == 0 {
		return value
	}
	if replaced := w.leafReplacement(v, value); replaced != nil {
		return replaced
	}
	if value.strSize > 0 || length > w.chars {
		w.chars = 0
		return w.limit(w.e.spec.algorithms.RuleIDs.SizeLimit)
	}
	w.chars -= length
	return stringNode(w.scanUnits(value.str))
}

// scanUnits runs the rules of the tier on one leaf. A failure replaces that leaf: the full tier
// handles it itself (SPEC 9.4); in the standard tier, strict mode replaces the leaf and compat
// mode ends the whole walk (recovered by the caller).
func (w *walker) scanUnits(units []uint16) (out []uint16) {
	if w.strict && w.mode.tier == TierStandard {
		defer func() {
			if recover() != nil {
				w.rec.add(w.e.spec.algorithms.RuleIDs.Failed)
				out = w.e.placeholders.readUnits(w.e.spec.algorithms.RuleIDs.Failed)
			}
		}()
	}
	return w.e.scan(units, w.mode, w.rec)
}

// enter visits one value. A leaf is finished at once; a container opens a frame.
func (w *walker) enter(value *node, v Verdict, depth int) (*node, *frame) {
	ruleIDs := &w.e.spec.algorithms.RuleIDs
	if w.nodes <= 0 {
		return w.limit(ruleIDs.SizeLimit), nil
	}
	w.nodes--
	if value.kind == kindString {
		return w.scanLeaf(value, v), nil
	}
	if value.isPrimitive() {
		if replaced := w.leafReplacement(v, value); replaced != nil {
			return replaced, nil
		}
		return value, nil
	}
	if depth >= w.maxDepth {
		return w.limit(ruleIDs.DepthLimit), nil
	}
	out := &node{kind: value.kind}
	return nil, &frame{src: value, out: out, verdict: v, depth: depth}
}

func (w *walker) isSkipKey(key []uint16) bool {
	for _, skip := range w.skip {
		if equalUnits(skip, key) {
			return true
		}
	}
	return false
}

// redactKey is the key as written, or its placeholder form when the key text holds a secret. A key
// is scanned with the rules of the tier (in the full tier a key that is itself a token is replaced),
// when its length is within the key bounds.
func (w *walker) redactKey(key []uint16) []uint16 {
	limits := w.e.spec.algorithms
	if len(key) < limits.Text.MinScanLength || len(key) > limits.Sync.MaxKeyChars {
		return key
	}
	return w.e.scan(key, w.mode, w.rec)
}

// strictKey scans a key against the character budget; one that does not fit becomes a placeholder.
func (w *walker) strictKey(key []uint16) []uint16 {
	ruleIDs := &w.e.spec.algorithms.RuleIDs
	if len(key) > w.e.spec.algorithms.Sync.MaxKeyChars || len(key) > w.chars {
		w.chars = 0
		return w.limit(ruleIDs.SizeLimit).str
	}
	w.chars -= len(key)
	return w.redactKey(key)
}

// cut closes a frame early: what is left of it collapses into one size-limit marker. `rawKey` is
// the key of the first entry that was not visited (an object; compat keeps it as it was).
func (w *walker) cut(top *frame, rawKey []uint16) {
	marker := w.limit(w.e.spec.algorithms.RuleIDs.SizeLimit)
	if !top.isArray() {
		top.outKey = rawKey
		if w.strict {
			top.outKey = marker.str
		}
	}
	w.place(top, marker)
	top.idx = entryCount(top.src)
	top.cutDone = true
}

// cutHere cuts a frame whose next entry is built but cannot be visited: the node budget is spent.
func (w *walker) cutHere(top *frame) {
	if top.isArray() {
		w.cut(top, nil)
		return
	}
	w.cut(top, top.src.members[top.idx].key)
}

func (w *walker) descend(top *frame, value *node, v Verdict) *frame {
	finished, opened := w.enter(value, v, top.depth+1)
	if opened != nil {
		return opened
	}
	w.place(top, finished)
	return nil
}

// step handles the next entry of the top frame; it returns a frame to push when the entry is a
// container.
func (w *walker) step(top *frame) *frame {
	at := top.idx
	top.idx++
	if top.isArray() {
		return w.descend(top, top.src.items[at], top.verdict)
	}
	entry := top.src.members[at]
	top.outKey = w.outputKey(entry.key)
	if w.isSkipKey(entry.key) && entry.val.isPrimitive() {
		return w.skipValue(top, entry.val)
	}
	childVerdict := strongerVerdict(top.verdict, w.e.keys.keyVerdict(entry.key))
	return w.descend(top, entry.val, childVerdict)
}

func (w *walker) outputKey(key []uint16) []uint16 {
	if w.strict {
		return w.strictKey(key)
	}
	return w.redactKey(key)
}

// skipValue handles a primitive under a skip key. It is exempt from the key-context replacement
// only: strict scans a string, compat keeps it as it is.
func (w *walker) skipValue(top *frame, value *node) *frame {
	if w.strict && value.kind == kindString {
		return w.descend(top, value, VerdictNone)
	}
	w.nodes--
	w.place(top, value)
	return nil
}

func (w *walker) walk(root *node) *node {
	finished, opened := w.enter(root, VerdictNone, 0)
	if opened == nil {
		return finished
	}
	stack := []*frame{opened}
	for {
		top := stack[len(stack)-1]
		if top.done() && top.src.cut && !top.cutDone {
			w.cut(top, top.src.cutKey)
			continue
		}
		if top.done() {
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return top.out
			}
			w.place(stack[len(stack)-1], top.out)
			continue
		}
		if w.nodes <= 0 {
			w.cutHere(top)
			continue
		}
		if child := w.step(top); child != nil {
			stack = append(stack, child)
		}
	}
}
