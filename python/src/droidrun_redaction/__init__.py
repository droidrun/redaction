"""droidrun-redaction: secret redaction for text and JSON values.

The Python implementation of the redaction spec (`spec/SPEC.md`), standard and full tier. It redacts
byte for byte like the TypeScript package `@droidrun/redaction`. The default mode is `strict`: no path
returns a value that was not scanned.
"""

import math
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal, NamedTuple

from ._detect import Detect
from ._keys import KeyVerdict, is_secret_key_name, key_verdict
from ._placeholder import build_read_placeholder
from ._scan import (
    RULE_IDS,
    STRICT_LIMITS,
    SYNC_LIMITS,
    Scan,
    scan_capped,
    scan_full_compat,
    scan_full_strict,
    scan_standard,
    tally,
)
from ._spec import KEYS
from ._units import from_units
from ._walk import WalkState, walk_json

__all__ = [
    "KeyVerdict",
    "RedactResult",
    "RuleCount",
    "is_secret_key_name",
    "key_verdict",
    "redact_json",
    "redact_text",
]

Mode = Literal["strict", "compat"]
Tier = Literal["standard", "full"]
_MODES = ("strict", "compat")
_TIERS = ("standard", "full")


class RuleCount(NamedTuple):
    """How many times one rule redacted something. Ranges are not exposed: they reveal lengths."""

    rule_id: str
    count: int


@dataclass(frozen=True)
class RedactResult:
    """`value` is the redacted text or JSON value, `hits` the rule counts in order of first hit.

    `error` is None when every scan ran. Otherwise it is the class name (never a message, which could echo the
    input) of the first failure of a scan: `value` is then the placeholder `[REDACTED:redaction-failed]` or
    `[REDACTED:error]` (the whole text, or a JSON leaf), or, in the full tier's `compat` mode, the result of
    the standard rules that took over after the full-tier rules failed. A caller that must not send a
    degraded result checks `error`.
    """

    value: Any
    hits: tuple[RuleCount, ...]
    error: str | None


def _check_mode(mode: str) -> bool:
    if mode not in _MODES:
        raise ValueError("mode must be 'strict' or 'compat'")
    return mode == "strict"


def _check_tier(tier: str) -> bool:
    if tier not in _TIERS:
        raise ValueError("tier must be 'standard' or 'full'")
    return tier == "full"


def _check_limit(name: str, value: int | None, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _refuse_limits(**limits: int | None) -> None:
    """The full tier's `compat` mode has no limits (it is TypeScript's behaviour): a limit is an error."""
    given = [name for name, value in limits.items() if value is not None]
    if given:
        raise ValueError(
            f"{', '.join(given)} cannot be used with tier='full', mode='compat' (it has no limits)"
        )


def _result(value: Any, counts: dict[str, int], error: str | None = None) -> RedactResult:
    return RedactResult(value, tuple(RuleCount(*item) for item in counts.items()), error)


def _failed(error: Exception) -> RedactResult:
    rule_id = RULE_IDS["failed"]
    return RedactResult(build_read_placeholder(rule_id), (RuleCount(rule_id, 1),), type(error).__name__)


def _check_pii(pii: bool) -> bool:
    if not isinstance(pii, bool):
        raise TypeError("pii must be a bool")
    return pii


def _redact_text(text: str, limit: int | None, scan: Scan, options: Detect) -> RedactResult:
    counts: dict[str, int] = {}
    try:
        scanned, hits, error = scan_capped(text, limit, scan, options)
    except Exception as failure:
        return _failed(failure)
    tally(counts, hits)
    return _result(from_units(scanned), counts, error)


def redact_text(
    text: str,
    *,
    tier: Tier = "standard",
    mode: Mode = "strict",
    pii: bool = False,
    max_chars: int | None = None,
) -> RedactResult:
    """Redact the secrets in `text` with the rules of `tier` (`"standard"` or `"full"`).

    `pii=True` also redacts emails, phone numbers, IP addresses and one-time codes (SPEC 9.5).

    A text longer than `max_chars` (default 4,000,000 UTF-16 units) is replaced whole by
    `[REDACTED:size-limit]`. The full tier's `compat` mode is TypeScript's behaviour, which has no cap: giving
    `max_chars` with it raises `ValueError`. Never raises for the content of `text`.
    """
    strict = _check_mode(mode)
    is_full = _check_tier(tier)
    options = Detect(strict, _check_pii(pii))
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    if not is_full:
        limit = _check_limit("max_chars", max_chars, SYNC_LIMITS["maxChars"])
        return _redact_text(text, limit, scan_standard, options)
    if not strict:
        _refuse_limits(max_chars=max_chars)
        return _redact_text(text, None, scan_full_compat, options)
    limit = _check_limit("max_chars", max_chars, STRICT_LIMITS["maxChars"])
    return _redact_text(text, limit, scan_full_strict, options)


def redact_json(
    value: Any,
    *,
    tier: Tier = "standard",
    mode: Mode = "strict",
    pii: bool = False,
    skip_keys: Iterable[str] | None = None,
    max_depth: int | None = None,
    max_nodes: int | None = None,
    max_chars: int | None = None,
) -> RedactResult:
    """Redact the secrets in a parsed JSON value (dict, list, str, int, float, bool, None).

    Every string and every object key is scanned with the rules of `tier` (a key that is itself a token is
    replaced by its placeholder). The full tier's `compat` mode is TypeScript's behaviour, which has no depth,
    node or character limit: giving `max_depth`, `max_nodes` or `max_chars` with it raises `ValueError`.

    `pii=True` also redacts emails, phone numbers, IP addresses and one-time codes (SPEC 9.5), in strings and in
    keys.

    Every string is scanned, a string under a secret key name is replaced, and so is a number under a
    singular secret key (`pin`, not `max_tokens`). Output keys keep the ECMAScript order. A value outside
    the JSON model becomes `[REDACTED:redaction-failed]`. `skip_keys` (default `type`, `id`) lists keys
    whose scalar values are never replaced because of a secret parent key; in `strict` they are still scanned.
    """
    strict = _check_mode(mode)
    is_full = _check_tier(tier)
    options = Detect(strict, _check_pii(pii))
    limits = STRICT_LIMITS if strict else SYNC_LIMITS
    unlimited = is_full and not strict
    if unlimited:
        _refuse_limits(max_nodes=max_nodes, max_chars=max_chars, max_depth=max_depth)
    if isinstance(skip_keys, str | bytes):
        raise TypeError("skip_keys must be a collection of str, not a single string")
    skip = frozenset(KEYS["structuralSkipKeys"] if skip_keys is None else skip_keys)
    if not all(isinstance(key, str) for key in skip):
        raise TypeError("skip_keys must hold str only")
    state = WalkState(
        math.inf if unlimited else _check_limit("max_nodes", max_nodes, limits["maxNodes"]),
        math.inf if unlimited else _check_limit("max_chars", max_chars, limits["maxChars"]),
        math.inf if unlimited else _check_limit("max_depth", max_depth, limits["maxDepth"]),
        skip,
        options,
        is_full,
    )
    try:
        out = walk_json(value, state)
    except Exception as error:
        return _failed(error)
    return _result(out, state.counts, state.error)
