"""droidrun-redaction: secret redaction for text and JSON values.

The Python implementation of the standard tier of the redaction spec (`spec/SPEC.md`). It redacts
byte for byte like the TypeScript package `@droidrun/redaction`. The default mode is `strict`: no path
returns a value that was not scanned.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal, NamedTuple

from ._keys import is_secret_key_name
from ._placeholder import build_read_placeholder
from ._scan import RULE_IDS, STRICT_LIMITS, SYNC_LIMITS, scan_text
from ._spec import KEYS
from ._units import from_units, to_units
from ._walk import WalkState, walk_json

__all__ = ["RedactResult", "RuleCount", "is_secret_key_name", "redact_json", "redact_text"]

Mode = Literal["strict", "compat"]
_MODES = ("strict", "compat")


class RuleCount(NamedTuple):
    """How many times one rule redacted something. Ranges are not exposed: they reveal lengths."""

    rule_id: str
    count: int


@dataclass(frozen=True)
class RedactResult:
    """`value` is the redacted text or JSON value, `hits` the rule counts in order of first hit.

    `error` is None, or the class name of the failure that made `value` the placeholder
    `[REDACTED:redaction-failed]` (never a message: it could echo the input).
    """

    value: Any
    hits: tuple[RuleCount, ...]
    error: str | None


def _check_mode(mode: str) -> bool:
    if mode not in _MODES:
        raise ValueError("mode must be 'strict' or 'compat'")
    return mode == "strict"


def _check_limit(name: str, value: int | None, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _failed(error: Exception) -> RedactResult:
    rule_id = RULE_IDS["failed"]
    return RedactResult(build_read_placeholder(rule_id), (RuleCount(rule_id, 1),), type(error).__name__)


def redact_text(text: str, *, mode: Mode = "strict", max_chars: int | None = None) -> RedactResult:
    """Redact the secrets in `text` with the standard rules.

    A text longer than `max_chars` (default 4,000,000 UTF-16 units) is replaced whole by
    `[REDACTED:size-limit]`. Never raises for the content of `text`.
    """
    _check_mode(mode)
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    limit = _check_limit("max_chars", max_chars, SYNC_LIMITS["maxChars"])
    try:
        scanned, hits = scan_text(to_units(text), limit)
    except Exception as error:
        return _failed(error)
    counts: dict[str, int] = {}
    for rule_id, _start, _end in hits:
        counts[rule_id] = counts.get(rule_id, 0) + 1
    return RedactResult(from_units(scanned), tuple(RuleCount(*item) for item in counts.items()), None)


def redact_json(
    value: Any,
    *,
    mode: Mode = "strict",
    skip_keys: Iterable[str] | None = None,
    max_depth: int | None = None,
    max_nodes: int | None = None,
    max_chars: int | None = None,
) -> RedactResult:
    """Redact the secrets in a parsed JSON value (dict, list, str, int, float, bool, None).

    Every string is scanned, a string under a secret key name is replaced, and so is a number under a
    singular secret key (`pin`, not `max_tokens`). Output keys keep the ECMAScript order. A value outside
    the JSON model becomes `[REDACTED:redaction-failed]`. `skip_keys` (default `type`, `id`) lists keys
    whose scalar values are never replaced because of a secret parent key; in `strict` they are still scanned.
    """
    strict = _check_mode(mode)
    limits = STRICT_LIMITS if strict else SYNC_LIMITS
    skip = frozenset(KEYS["structuralSkipKeys"] if skip_keys is None else skip_keys)
    state = WalkState(
        _check_limit("max_nodes", max_nodes, limits["maxNodes"]),
        _check_limit("max_chars", max_chars, limits["maxChars"]),
        _check_limit("max_depth", max_depth, limits["maxDepth"]),
        skip,
        strict,
    )
    try:
        out = walk_json(value, state)
    except Exception as error:
        return _failed(error)
    return RedactResult(out, tuple(RuleCount(*item) for item in state.counts.items()), None)
