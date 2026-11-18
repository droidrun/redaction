"""The JSON walker (SPEC 8, 9.2 and 9.3): iterative, bounded by depth, nodes and characters.

One walker serves both modes. `compat` reproduces the TypeScript v0.2.0 behaviour; `strict` never
returns a value it did not scan (a skip-key string is scanned, a key is counted against the character
budget, the rest of a node-exhausted container collapses into one marker).
"""

import math
import re
from dataclasses import dataclass
from typing import Any

from ._detect import Hit
from ._keys import key_verdict, stronger_verdict
from ._placeholder import build_read_placeholder, is_whole_placeholder, number_last_placeholder
from ._scan import (
    RULE_IDS,
    is_overlong_key,
    redact_key,
    scan_full_compat,
    scan_full_strict,
    scan_standard,
    scan_units,
    tally,
)
from ._units import from_units, to_units

_ARRAY_INDEX = re.compile("(?:0|[1-9][0-9]*)", re.ASCII)
_MAX_ARRAY_INDEX = 4294967294
_MAX_ARRAY_INDEX_DIGITS = len(str(_MAX_ARRAY_INDEX))
_KEY_CONTEXT = RULE_IDS["keyContext"]
_SIZE_LIMIT = RULE_IDS["sizeLimit"]
_DEPTH_LIMIT = RULE_IDS["depthLimit"]
_CIRCULAR = RULE_IDS["circular"]
_FAILED = RULE_IDS["failed"]


class _OutsideModel(Exception):
    """A value the JSON model does not have (not a result: handled where the value is entered)."""


@dataclass
class _Frame:
    source: Any
    keys: list[str] | None
    items: list[Any]
    out: Any
    verdict: str
    depth: int
    index: int = 0
    out_key: str = ""
    cur_key: str = ""


class WalkState:
    def __init__(
        self,
        max_nodes: float,
        max_chars: float,
        max_depth: float,
        skip: frozenset[str],
        strict: bool,
        full: bool = False,
    ):
        self.full = full
        self.nodes = max_nodes
        self.chars = max_chars
        self.max_depth = max_depth
        self.skip = skip
        self.strict = strict
        self.counts: dict[str, int] = {}
        self.error: str | None = None
        self.ancestors: set[int] = set()

    def count(self, rule_id: str, times: int = 1) -> None:
        self.counts[rule_id] = self.counts.get(rule_id, 0) + times

    def count_hits(self, hits: list[Hit]) -> None:
        tally(self.counts, hits)

    def limit(self, rule_id: str) -> str:
        self.count(rule_id)
        return build_read_placeholder(rule_id)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, bool, int, float))


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _checked_number(value: int | float) -> int | float:
    """A number the package keeps: an integer exactly as given, a float only when it is finite."""
    if isinstance(value, float) and not math.isfinite(value):
        raise _OutsideModel
    return value


def _contract_keys(mapping: dict[Any, Any]) -> list[Any]:
    """Own-property order of ECMAScript: array-index keys ascending, then the others in insertion order."""
    keys = list(mapping)
    indexes = [key for key in keys if isinstance(key, str) and _is_array_index(key)]
    if not indexes:
        return keys
    indexes.sort(key=int)
    return indexes + [key for key in keys if not (isinstance(key, str) and _is_array_index(key))]


def _is_array_index(key: str) -> bool:
    # A longer key is no index; checked first, so a huge digit string never reaches `int` (its size limit).
    if len(key) > _MAX_ARRAY_INDEX_DIGITS or _ARRAY_INDEX.fullmatch(key) is None:
        return False
    return int(key) <= _MAX_ARRAY_INDEX


def _leaf_replacement(verdict: str, value: Any) -> str | None:
    """The placeholder that replaces a leaf under `verdict`, or None when it stays (SPEC section 6)."""
    if verdict == "none":
        return None
    if isinstance(value, str):
        if value == "" or is_whole_placeholder(value):
            return None
        return build_read_placeholder(_KEY_CONTEXT)
    if _is_number(value) and verdict == "any":
        return build_read_placeholder(_KEY_CONTEXT)
    return None


def _scan_leaf_text(units: str, state: WalkState) -> str:
    if state.full:
        scanned, hits, error = (scan_full_strict if state.strict else scan_full_compat)(units)
        state.error = state.error or error
    elif not state.strict:
        scanned, hits = scan_units(units)
    else:
        try:
            scanned, hits = scan_units(units)
        except Exception as failure:
            state.error = state.error or type(failure).__name__
            return state.limit(_FAILED)
    state.count_hits(hits)
    return from_units(scanned)


def _string_leaf(value: str, verdict: str, state: WalkState) -> str:
    if value == "":
        return value
    keyed = _leaf_replacement(verdict, value)
    if keyed is not None:
        state.count(_KEY_CONTEXT)
        return keyed
    # A text has at least as many units as characters, so a text over the budget by characters is over it
    # by units: no conversion for it.
    if len(value) > state.chars:
        state.chars = 0
        return state.limit(_SIZE_LIMIT)
    units = to_units(value)
    if len(units) > state.chars:
        state.chars = 0
        return state.limit(_SIZE_LIMIT)
    state.chars -= len(units)
    return _scan_leaf_text(units, state)


def _scalar_leaf(value: Any, verdict: str, state: WalkState) -> Any:
    if _is_number(value):
        value = _checked_number(value)
    keyed = _leaf_replacement(verdict, value)
    if keyed is None:
        return value
    state.count(_KEY_CONTEXT)
    return keyed


def _open_frame(value: Any, verdict: str, depth: int, state: WalkState) -> _Frame | str:
    if isinstance(value, list):
        return _Frame(value, None, value, [], verdict, depth)
    keys = _contract_keys(value)
    if not all(isinstance(key, str) for key in keys):
        return state.limit(_FAILED)
    return _Frame(value, keys, [value[key] for key in keys], [], verdict, depth)


def _enter(value: Any, verdict: str, depth: int, state: WalkState) -> tuple[_Frame | None, Any]:
    """Start a value: a leaf gives (None, its output), a container gives (its frame, None)."""
    if state.nodes <= 0:
        return None, state.limit(_SIZE_LIMIT)
    state.nodes -= 1
    if isinstance(value, str):
        return None, _string_leaf(value, verdict, state)
    try:
        if _is_scalar(value):
            return None, _scalar_leaf(value, verdict, state)
    except _OutsideModel:
        return None, state.limit(_FAILED)
    if not isinstance(value, (list, dict)):
        return None, state.limit(_FAILED)
    if depth >= state.max_depth:
        return None, state.limit(_DEPTH_LIMIT)
    if id(value) in state.ancestors:
        return None, state.limit(_CIRCULAR)
    frame = _open_frame(value, verdict, depth, state)
    if isinstance(frame, str):
        return None, frame
    state.ancestors.add(id(value))
    return frame, None


def _over_budget(state: WalkState) -> str:
    state.chars = 0
    return state.limit(_SIZE_LIMIT)


def _next_key(key: str, state: WalkState) -> str:
    """The output key of the next object entry."""
    # A key has at least as many units as characters: one over a limit by characters is over it by units.
    if is_overlong_key(key) and not state.strict:
        return key
    if state.strict and (is_overlong_key(key) or len(key) > state.chars):
        return _over_budget(state)
    units = to_units(key)
    if state.strict:
        if is_overlong_key(units) or len(units) > state.chars:
            return _over_budget(state)
        state.chars -= len(units)
    scan = (scan_full_strict if state.strict else scan_full_compat) if state.full else scan_standard
    redacted, hits, error = redact_key(units, scan)
    state.error = state.error or error
    state.count_hits(hits)
    return key if not hits else from_units(redacted)


def _numbered(key: str, taken: dict[str, Any], reserved: set[str]) -> str:
    """`key` when no entry has it; else the key numbered inside its last placeholder (`[REDACTED:npm#2]`,
    `#3`, ...), skipping every name that is taken or reserved (SPEC L-P, L-Q)."""
    if key not in taken and key not in reserved:
        return key
    number = 2
    while (numbered := number_last_placeholder(key, number)) is not None:
        if numbered not in taken and numbered not in reserved:
            return numbered
        number += 1
    return key


def _assign_keys(entries: list[tuple[str, Any, bool]]) -> dict[str, Any]:
    """The object of the (output key, value, changed) entries of one object, in iteration order.

    No value is lost when keys redact to the same text. A key redaction left unchanged keeps its own name and
    is reserved first; only a changed key gets a number, in iteration order, on a collision (SPEC L-P, L-Q).
    """
    reserved = {key for key, _value, changed in entries if not changed}
    out: dict[str, Any] = {}
    for key, value, changed in entries:
        out[_numbered(key, out, reserved) if changed else key] = value
    return out


def _place(frame: _Frame, value: Any) -> None:
    if frame.keys is None:
        frame.out.append(value)
    else:
        frame.out.append((frame.out_key, value, frame.out_key != frame.cur_key))


def _nodes_exhausted(frame: _Frame, state: WalkState) -> None:
    """Close a container whose nodes ran out: the rest of it becomes one size-limit marker."""
    marker = state.limit(_SIZE_LIMIT)
    if frame.keys is not None:
        key_marker = build_read_placeholder(_SIZE_LIMIT)
        frame.cur_key = frame.keys[frame.index]
        frame.out_key = key_marker if state.strict else frame.cur_key
    _place(frame, marker)
    frame.index = len(frame.items)


def _skip_key_scalar(child: Any, state: WalkState) -> tuple[bool, Any]:
    """A skip-key value that is a scalar: (is it done here, its output)."""
    if isinstance(child, str) and state.strict:
        return False, child
    state.nodes -= 1
    if isinstance(child, str):
        return True, child
    try:
        return True, _checked_number(child) if _is_number(child) else child
    except _OutsideModel:
        return True, state.limit(_FAILED)


def walk_json(value: Any, state: WalkState) -> Any:
    """The output of the walk; the state keeps the hit counts."""
    stack: list[_Frame] = []
    pending: tuple[Any, str, int] | None = (value, "none", 0)
    while True:
        if pending is not None:
            frame, leaf = _enter(*pending, state)
            pending = None
            if frame is not None:
                stack.append(frame)
            elif not stack:
                return leaf
            else:
                _place(stack[-1], leaf)
        top = stack[-1]
        if top.index >= len(top.items):
            stack.pop()
            state.ancestors.discard(id(top.source))
            result = top.out if top.keys is None else _assign_keys(top.out)
            if not stack:
                return result
            _place(stack[-1], result)
            continue
        if state.nodes <= 0:
            _nodes_exhausted(top, state)
            continue
        index = top.index
        top.index += 1
        child = top.items[index]
        if top.keys is None:
            pending = (child, top.verdict, top.depth + 1)
            continue
        key = top.keys[index]
        top.cur_key = key
        top.out_key = _next_key(key, state)
        if key in state.skip and _is_scalar(child):
            done, output = _skip_key_scalar(child, state)
            if done:
                _place(top, output)
            else:
                pending = (child, "none", top.depth + 1)
            continue
        pending = (child, stronger_verdict(top.verdict, key_verdict(key)), top.depth + 1)
