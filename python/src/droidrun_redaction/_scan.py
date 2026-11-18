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


def scan_text(units: str, max_chars: int) -> tuple[str, list[Hit]]:
    """SPEC 9.1: a text over the cap is replaced whole, a short one is returned as it is."""
    if len(units) > max_chars:
        rule_id = RULE_IDS["sizeLimit"]
        return build_read_placeholder(rule_id), [(rule_id, 0, len(units))]
    return scan_units(units)


def redact_key(key_units: str) -> tuple[str, list[Hit]]:
    """The key as written, or its placeholder text when the key itself holds a secret."""
    if len(key_units) < MIN_SCAN_LENGTH or len(key_units) > SYNC_LIMITS["maxKeyChars"]:
        return key_units, []
    hits = detect(key_units)
    if not hits:
        return key_units, []
    return splice(key_units, hits), hits


def is_overlong_key(key_units: str) -> bool:
    return len(key_units) > SYNC_LIMITS["maxKeyChars"]
