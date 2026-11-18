/**
 * strict.ts — the strict-mode JSON walker: iterative (no recursion, so no stack
 * overflow on deep input), bounded by depth, node and total-character limits, and
 * it never returns text it did not scan (also under skip keys: they only exempt a
 * string from the key-context replacement, the leaf scanner still runs on it).
 * Whatever it cannot scan becomes a placeholder: `[REDACTED:size-limit]` past a node/character
 * limit or for an over-long key, `[REDACTED:depth-limit]` past the depth limit,
 * `[REDACTED:circular]` for a cycle, `[REDACTED:redaction-failed]` for a value outside the JSON model.
 *
 * The walker is a generator: it yields each string leaf and receives the scanned
 * result, so one traversal serves the sync and the async entry points. Limits and
 * placeholder ids are the spec's (`strict`, `ruleIds`).
 */
import { appendHits, applyHits, type Hit } from './hits.js';
import {
    KEY_CONTEXT_RULE_ID,
    keyVerdict,
    leafPlaceholder,
    strongerVerdict,
    type KeyVerdict,
} from './key-names.js';
import { keysHoldingPlaceholder, newPlacer, placeKey, type KeyPlacer } from './place-key.js';
import { isPrimitive } from './primitive.js';
import { buildReadPlaceholder } from './placeholder.js';
import { isOverlongKey, isScannableKey } from './redact-key.js';
import { ALGORITHMS_SPEC } from './spec.js';

const { ruleIds } = ALGORITHMS_SPEC;

export type StrictLimits = { maxChars: number; maxDepth: number; maxNodes: number };
export type LeafResult = { text: string; hits: Hit[] };
export type StrictWalk = Generator<string, unknown, LeafResult>;

export function strictLimits(opts: Partial<StrictLimits>): StrictLimits {
    const defaults = ALGORITHMS_SPEC.strict;
    return {
        maxChars: opts.maxChars ?? defaults.maxChars,
        maxDepth: opts.maxDepth ?? defaults.maxDepth,
        maxNodes: opts.maxNodes ?? defaults.maxNodes,
    };
}

type Frame = {
    source: object;
    keys: string[] | null;
    items: unknown[];
    index: number;
    out: unknown[] | Record<string, unknown>;
    verdict: KeyVerdict;
    depth: number;
    outKey: string;
    /** True when the scan or a limit changed the key (an unchanged key keeps its own name, SPEC 8). */
    changed: boolean;
    placer: KeyPlacer;
};

type Entered = { frame: Frame } | { value: unknown };

type State = {
    nodes: number;
    chars: number;
    limits: StrictLimits;
    skip: ReadonlySet<string>;
    hits: Hit[];
    ancestors: Set<object>;
};

function placeholderFor(ruleId: string, state: State): string {
    state.hits.push({ ruleId, range: [0, 0] });
    return buildReadPlaceholder(ruleId);
}

/** A string, number, boolean, null, bigint or undefined: a leaf the walker can place as it is. */
function isScalar(value: unknown): boolean {
    return isPrimitive(value) && typeof value !== 'symbol';
}

/** An object the JSON model has: a plain object or an array (not a class instance, Date or function). */
function isWalkable(value: unknown): value is object {
    if (typeof value !== 'object' || value === null) return false;
    return isPlainContainer(value);
}

function isPlainContainer(value: object): boolean {
    if (Array.isArray(value)) return true;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function* scanLeaf(value: string, verdict: KeyVerdict, state: State): Generator<string, string, LeafResult> {
    if (value.length === 0) return value;
    const keyed = leafPlaceholder(verdict, value);
    if (keyed !== undefined) {
        state.hits.push({ ruleId: KEY_CONTEXT_RULE_ID, range: [0, value.length] });
        return keyed;
    }
    if (value.length > state.chars) {
        state.chars = 0;
        return placeholderFor(ruleIds.sizeLimit, state);
    }
    state.chars -= value.length;
    const scanned = yield value;
    appendHits(state.hits, scanned.hits);
    return scanned.text;
}

function openFrame(value: object, verdict: KeyVerdict, depth: number, state: State): Frame {
    state.ancestors.add(value);
    const isArray = Array.isArray(value);
    const keys = isArray ? null : Object.keys(value);
    const items = isArray ? value : (keys as string[]).map((key) => (value as Record<string, unknown>)[key]);
    return {
        source: value,
        keys,
        items,
        index: 0,
        out: isArray ? [] : {},
        verdict,
        depth,
        outKey: '',
        changed: false,
        placer: newPlacer(),
    };
}

function* enter(
    value: unknown,
    verdict: KeyVerdict,
    depth: number,
    state: State,
): Generator<string, Entered, LeafResult> {
    if (state.nodes <= 0) return { value: placeholderFor(ruleIds.sizeLimit, state) };
    state.nodes -= 1;
    if (typeof value === 'string') return { value: yield* scanLeaf(value, verdict, state) };
    if (isScalar(value)) {
        const keyed = leafPlaceholder(verdict, value);
        if (keyed === undefined) return { value };
        state.hits.push({ ruleId: KEY_CONTEXT_RULE_ID, range: [0, 0] });
        return { value: keyed };
    }
    if (!isWalkable(value)) {
        return { value: placeholderFor(ruleIds.failed, state) };
    }
    if (depth >= state.limits.maxDepth) return { value: placeholderFor(ruleIds.depthLimit, state) };
    if (state.ancestors.has(value)) return { value: placeholderFor(ruleIds.circular, state) };
    const frame = openFrame(value, verdict, depth, state);
    if (frame.keys !== null) frame.placer = newPlacer(yield* reservedKeys(frame.keys, state.chars));
    return { frame };
}

/** The input keys that hold a placeholder and that the key scan leaves as they are (SPEC 8): scanned once,
 *  through the leaf scanner, without a budget charge and without hits. Only a key that fits the budget can be
 *  left as it is (a later one becomes the size-limit placeholder), so the scan stops where the running total
 *  of the keys' lengths passes the remaining budget: the work is bounded by `maxChars`. */
function* reservedKeys(keys: string[], budget: number): Generator<string, Set<string>, LeafResult> {
    const reserved = new Set<string>();
    const candidates = new Set(keysHoldingPlaceholder(keys));
    let total = 0;
    for (const key of keys) {
        total += key.length;
        if (total > budget) break;
        if (!candidates.has(key) || isOverlongKey(key)) continue;
        if ((yield key).text === key) reserved.add(key);
    }
    return reserved;
}

/** The key of the next entry, scanned by the leaf scanner (so the tier and `opts.detect` apply to keys as to
 *  leaves), or its size-limit placeholder. */
function* nextKey(
    key: string,
    state: State,
): Generator<string, { outKey: string; changed: boolean }, LeafResult> {
    if (isOverlongKey(key) || key.length > state.chars) {
        state.chars = 0;
        return { outKey: placeholderFor(ruleIds.sizeLimit, state), changed: true };
    }
    state.chars -= key.length;
    if (!isScannableKey(key)) return { outKey: key, changed: false };
    const scanned = yield key;
    appendHits(state.hits, scanned.hits);
    return { outKey: scanned.text, changed: scanned.text !== key };
}

function place(frame: Frame, value: unknown): void {
    if (frame.keys === null) {
        (frame.out as unknown[]).push(value);
        return;
    }
    placeKey(frame.out as Record<string, unknown>, frame.placer, frame.outKey, frame.changed, value);
}

/** Close a frame early: what is left of it collapses into one size-limit marker. */
function collapse(frame: Frame, state: State): void {
    frame.outKey = buildReadPlaceholder(ruleIds.sizeLimit);
    frame.changed = true;
    place(frame, placeholderFor(ruleIds.sizeLimit, state));
    frame.index = frame.items.length;
}

export function* strictWalk(
    root: unknown,
    limits: StrictLimits,
    skip: ReadonlySet<string>,
    hits: Hit[],
): StrictWalk {
    const state: State = {
        nodes: limits.maxNodes,
        chars: limits.maxChars,
        limits,
        skip,
        hits,
        ancestors: new Set(),
    };
    const stack: Frame[] = [];
    let pending: { value: unknown; verdict: KeyVerdict; depth: number } | undefined = {
        value: root,
        verdict: 'none',
        depth: 0,
    };
    for (;;) {
        if (pending !== undefined) {
            const entered = yield* enter(pending.value, pending.verdict, pending.depth, state);
            pending = undefined;
            if ('frame' in entered) {
                stack.push(entered.frame);
            } else if (stack.length === 0) {
                return entered.value;
            } else {
                place(stack[stack.length - 1] as Frame, entered.value);
            }
        }
        const top = stack[stack.length - 1] as Frame;
        if (top.index >= top.items.length) {
            stack.pop();
            state.ancestors.delete(top.source);
            if (stack.length === 0) return top.out;
            place(stack[stack.length - 1] as Frame, top.out);
            continue;
        }
        if (state.nodes <= 0) {
            collapse(top, state);
            continue;
        }
        const index = top.index;
        top.index += 1;
        const child = top.items[index];
        if (top.keys === null) {
            pending = { value: child, verdict: top.verdict, depth: top.depth + 1 };
            continue;
        }
        const key = top.keys[index] as string;
        const next = yield* nextKey(key, state);
        top.outKey = next.outKey;
        top.changed = next.changed;
        if (state.skip.has(key) && isPrimitive(child)) {
            // A skip key only exempts a value from the key-context replacement: a string is still scanned.
            if (typeof child === 'string') {
                pending = { value: child, verdict: 'none', depth: top.depth + 1 };
            } else {
                state.nodes -= 1;
                place(top, child);
            }
            continue;
        }
        const childVerdict = strongerVerdict(top.verdict, keyVerdict(key));
        pending = { value: child, verdict: childVerdict, depth: top.depth + 1 };
    }
}

/** Run the walker with a sync leaf scanner. */
export function runStrictSync(walk: StrictWalk, scan: (text: string) => LeafResult): unknown {
    let step = walk.next();
    while (step.done !== true) step = walk.next(scan(step.value));
    return step.value;
}

/** Run the walker with an async leaf scanner. */
export async function runStrictAsync(
    walk: StrictWalk,
    scan: (text: string) => Promise<LeafResult>,
): Promise<unknown> {
    let step = walk.next();
    while (step.done !== true) step = walk.next(await scan(step.value));
    return step.value;
}

/** Apply hits to a string the way the strict leaf scanner does. */
export function spliceHits(text: string, hits: Hit[]): LeafResult {
    return { text: applyHits(text, hits), hits };
}
