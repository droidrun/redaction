/**
 * strict.ts — the strict-mode JSON walker: iterative (no recursion, so no stack
 * overflow on deep input), bounded by depth, node and total-character limits, and
 * it never returns text it did not scan. Whatever it cannot scan becomes a
 * placeholder: `[REDACTED:size-limit]` past a node/character limit or for an over-long
 * key, `[REDACTED:depth-limit]` past the depth limit, `[REDACTED:circular]` for a
 * cycle, `[REDACTED:redaction-failed]` for a value outside the JSON model.
 *
 * The walker is a generator: it yields each string leaf and receives the scanned
 * result, so one traversal serves the sync and the async entry points. Limits and
 * placeholder ids are the spec's (`strict`, `ruleIds`).
 */
import { applyHits, type Hit } from './hits.js';
import {
    KEY_CONTEXT_RULE_ID,
    keyVerdict,
    leafPlaceholder,
    strongerVerdict,
    type KeyVerdict,
} from './key-names.js';
import { setOwnKey } from './own-key.js';
import { buildReadPlaceholder } from './placeholder.js';
import { isOverlongKey, redactKey } from './redact-key.js';
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

function isPrimitive(value: unknown): boolean {
    return value === null || (typeof value !== 'object' && typeof value !== 'function');
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
    state.hits.push(...scanned.hits);
    return scanned.text;
}

function openFrame(value: object, verdict: KeyVerdict, depth: number, state: State): Frame {
    state.ancestors.add(value);
    const isArray = Array.isArray(value);
    const keys = isArray ? null : Object.keys(value);
    const items = isArray ? value : (keys as string[]).map((key) => (value as Record<string, unknown>)[key]);
    return { source: value, keys, items, index: 0, out: isArray ? [] : {}, verdict, depth, outKey: '' };
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
    if (isPrimitive(value) && typeof value !== 'symbol') {
        const keyed = leafPlaceholder(verdict, value);
        if (keyed === undefined) return { value };
        state.hits.push({ ruleId: KEY_CONTEXT_RULE_ID, range: [0, 0] });
        return { value: keyed };
    }
    if (typeof value !== 'object' || value === null || !isPlainContainer(value)) {
        return { value: placeholderFor(ruleIds.failed, state) };
    }
    if (depth >= state.limits.maxDepth) return { value: placeholderFor(ruleIds.depthLimit, state) };
    if (state.ancestors.has(value)) return { value: placeholderFor(ruleIds.circular, state) };
    return { frame: openFrame(value, verdict, depth, state) };
}

/** The key of the next entry, scanned, or its size-limit placeholder. */
function nextKey(key: string, state: State): string {
    if (isOverlongKey(key) || key.length > state.chars) {
        state.chars = 0;
        return placeholderFor(ruleIds.sizeLimit, state);
    }
    state.chars -= key.length;
    return redactKey(key, state.hits);
}

function place(frame: Frame, value: unknown): void {
    if (frame.keys === null) {
        (frame.out as unknown[]).push(value);
        return;
    }
    setOwnKey(frame.out as Record<string, unknown>, frame.outKey, value);
}

/** Close a frame early: what is left of it collapses into one size-limit marker. */
function collapse(frame: Frame, state: State): void {
    frame.outKey = buildReadPlaceholder(ruleIds.sizeLimit);
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
        top.outKey = nextKey(key, state);
        if (state.skip.has(key) && isPrimitive(child)) {
            state.nodes -= 1;
            place(top, child);
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
