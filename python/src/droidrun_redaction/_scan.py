"""Scanning one text (SPEC 9.1) and one object key (SPEC section 8) with the standard rules."""

from ._detect import Hit, detect, splice
from ._placeholder import build_read_placeholder
from ._spec import ALGORITHMS

RULE_IDS = ALGORITHMS["ruleIds"]
MIN_SCAN_LENGTH: int = ALGORITHMS["text"]["minScanLength"]
SYNC_LIMITS = ALGORITHMS["sync"]
STRICT_LIMITS = ALGORITHMS["strict"]


def scan_units(units: str) -> tuple[str, list[Hit]]:
    """The unit string with its secrets replaced, and the hits (no length cap here)."""
    if len(units) < MIN_SCAN_LENGTH:
        return units, []
    hits = detect(units)
    return splice(units, hits), hits


def tally(counts: dict[str, int], hits: list[Hit]) -> None:
    """Add one to the count of each hit's rule (ranges are dropped here: they reveal lengths)."""
    for rule_id, _start, _end in hits:
        counts[rule_id] = counts.get(rule_id, 0) + 1


def oversize_text(length: int) -> tuple[str, list[Hit]]:
    """What a text of `length` units over the cap becomes (SPEC 9.1): the size-limit placeholder."""
    rule_id = RULE_IDS["sizeLimit"]
    return build_read_placeholder(rule_id), [(rule_id, 0, length)]


def scan_text(units: str, max_chars: int) -> tuple[str, list[Hit]]:
    """SPEC 9.1: a text over the cap is replaced whole, a short one is returned as it is."""
    if len(units) > max_chars:
        return oversize_text(len(units))
    return scan_units(units)


def redact_key(key_units: str) -> tuple[str, list[Hit]]:
    """The key with its secrets replaced (a key over `maxKeyChars` is left as it is), and the hits."""
    if is_overlong_key(key_units):
        return key_units, []
    return scan_units(key_units)


def is_overlong_key(key_units: str) -> bool:
    return len(key_units) > SYNC_LIMITS["maxKeyChars"]
