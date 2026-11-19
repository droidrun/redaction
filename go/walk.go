package redaction

// walker is the iterative JSON walk of SPEC 9.2 (compat) and 9.3 (strict). It never recurses, so
// deep input costs no stack.
type walker struct {
	e        *engine
	mode     scanMode
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
	// budget is what was left of the character budget when the frame opened (strict reservation).
	budget  int
	outKey  []uint16
	index   map[string]int
	cutDone bool
	// keyChanged: redaction changed the key of the entry being placed (an unchanged key is its own).
	keyChanged bool
	// inputNames are the input keys of the object by name, also those that were left out under a node limit
	// and hold a placeholder (made when a changed key needs them), and unchanged says per name whether
	// redaction leaves that key as it is.
	inputNames map[string][]uint16
	unchanged  map[string]bool
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
// array). SPEC 8, key collisions: a key that redaction leaves unchanged keeps its own name, and
// that name is reserved for it before any numbering, wherever the entry stands in the object (also when the
// entry is left out under a node limit). A changed key whose name is taken (by an earlier entry, or
// reserved) gets a number inside its last placeholder, `[REDACTED:rule#2]`, `#3`, ... in contract order,
// skipping taken names. Any other key keeps the old rule: the later value replaces the earlier one and the
// key keeps the earlier position (no duplicate key is ever written).
func (w *walker) place(f *frame, value *node) {
	if f.isArray() {
		f.out.items = append(f.out.items, value)
		return
	}
	if f.keyChanged && w.isTaken(f, f.outKey) {
		if at, numberable := w.e.placeholders.numberAt(f.outKey); numberable {
			f.addMember(w.numberedKey(f, f.outKey, at), value)
			return
		}
	}
	if !f.keyChanged && !containsUnits(f.outKey, redactedOpen) {
		// Input keys are distinct and only a placeholder key can equal an earlier output key.
		f.addMember(f.outKey, value)
		return
	}
	f.setMember(f.outKey, value)
}

// setMember stores the value under the key, replacing an earlier entry of that name.
func (f *frame) setMember(key []uint16, value *node) {
	if at := f.memberAt(key); at >= 0 {
		f.out.members[at].val = value
		return
	}
	f.addMember(key, value)
}

// isTaken: an earlier entry has that output key, or an input key that redaction leaves unchanged has it.
func (w *walker) isTaken(f *frame, key []uint16) bool {
	return f.memberAt(key) >= 0 || w.isReserved(f, key)
}

// isReserved: the object has an input key of that name that redaction leaves unchanged.
func (w *walker) isReserved(f *frame, key []uint16) bool {
	if f.inputNames == nil {
		f.inputNames = w.reservableNames(f)
		f.unchanged = make(map[string]bool)
	}
	name := unitsKey(key)
	input, found := f.inputNames[name]
	if !found {
		return false
	}
	unchanged, known := f.unchanged[name]
	if !known {
		unchanged = !w.wouldChange(input)
		f.unchanged[name] = unchanged
	}
	return unchanged
}

// reservableNames are the input keys of the object by name that can be reserved (SPEC 8 rule 1). In
// strict mode only a key that fits the character budget, counted over the keys in contract order, can
// be left as it is: a later one becomes the size-limit placeholder, so it is not reserved.
func (w *walker) reservableNames(f *frame) map[string][]uint16 {
	names := make(map[string][]uint16, len(f.src.members))
	total := 0
	fits := func(key []uint16) bool {
		total += len(key)
		return !w.mode.strict || total <= f.budget
	}
	for _, entry := range f.src.members {
		if fits(entry.key) {
			names[unitsKey(entry.key)] = entry.key
		}
	}
	if first := f.src.firstLeftOut(); first != nil && fits(first) { // known also without room for the others
		names[unitsKey(first)] = first
	}
	if f.src.left != nil {
		for _, left := range f.src.left.keys {
			if fits(left) {
				names[unitsKey(left)] = left
			}
		}
	}
	return names
}

// wouldChange: key redaction changes this key (it holds a secret, or it is over the limit in strict
// mode). It scans without recording anything.
func (w *walker) wouldChange(key []uint16) bool {
	limits := w.e.spec.algorithms
	if len(key) < limits.Text.MinScanLength {
		return false
	}
	if len(key) > limits.Sync.MaxKeyChars {
		return w.mode.strict
	}
	if w.mode.strict && w.mode.tier == TierFull && len(key) > w.mode.maxChars {
		// The strict full-tier scan replaces a text over the character limit by the size-limit
		// placeholder, a key too: the key is unchanged only when it reads exactly like that.
		sizeLimit := w.e.placeholders.readUnits(limits.RuleIDs.SizeLimit)
		return !equalUnits(key, sizeLimit)
	}
	t := newText(key)
	detect := func() []hit { return w.e.detect(t) }
	if w.mode.tier == TierFull {
		detect = func() []hit { return w.e.detectFull(t) }
	}
	hits, finished := w.e.tryDetect(detect)
	return !finished || len(hits) > 0
}

// numberedKey is the next free numbered form of a taken output key: the number starts at 2 and counts
// up per object and per key; a number whose key is taken is skipped. `at` is where the number goes.
func (w *walker) numberedKey(f *frame, key []uint16, at int) []uint16 {
	if f.lastNumber == nil {
		f.lastNumber = make(map[string]int)
	}
	base := unitsKey(key)
	last := max(f.lastNumber[base], 1)
	for {
		last++
		candidate := w.e.placeholders.numbered(key, at, last)
		if !w.isTaken(f, candidate) {
			f.lastNumber[base] = last
			return candidate
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
	if w.mode.strict && w.mode.tier == TierStandard {
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
	return nil, &frame{src: value, out: out, verdict: v, depth: depth, budget: w.chars}
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

// strictKey scans a key against the character budget; one that does not fit becomes a placeholder, and
// that is a change even when the key reads the same (a key written as `[REDACTED:size-limit]`).
func (w *walker) strictKey(key []uint16) (out []uint16, changed bool) {
	ruleIDs := &w.e.spec.algorithms.RuleIDs
	if len(key) > w.e.spec.algorithms.Sync.MaxKeyChars || len(key) > w.chars {
		w.chars = 0
		return w.limit(ruleIDs.SizeLimit).str, true
	}
	w.chars -= len(key)
	out = w.redactKey(key)
	return out, !equalUnits(out, key)
}

// cut closes a frame early: what is left of it collapses into one size-limit marker. `rawKey` is
// the key of the first entry that was not visited (an object; compat keeps it as it was).
func (w *walker) cut(top *frame, rawKey []uint16) {
	marker := w.limit(w.e.spec.algorithms.RuleIDs.SizeLimit)
	if !top.isArray() {
		top.outKey = rawKey
		top.keyChanged = w.mode.strict
		if w.mode.strict {
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
	top.outKey, top.keyChanged = w.outputKey(entry.key)
	if w.isSkipKey(entry.key) && entry.val.isPrimitive() {
		return w.skipValue(top, entry.val)
	}
	childVerdict := strongerVerdict(top.verdict, w.e.keys.keyVerdict(entry.key))
	return w.descend(top, entry.val, childVerdict)
}

func (w *walker) outputKey(key []uint16) (out []uint16, changed bool) {
	if w.mode.strict {
		return w.strictKey(key)
	}
	out = w.redactKey(key)
	return out, !equalUnits(out, key)
}

// skipValue handles a primitive under a skip key. It is exempt from the key-context replacement
// only: strict scans a string, compat keeps it as it is.
func (w *walker) skipValue(top *frame, value *node) *frame {
	if w.mode.strict && value.kind == kindString {
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
			w.cut(top, top.src.firstLeftOut())
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
