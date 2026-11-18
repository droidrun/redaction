"""Scanning one text (SPEC 9.1) and one object key (SPEC section 8) with the standard rules."""

from ._detect import Hit, detect, detect_full_rules, merge_hits, splice
from ._placeholder import build_read_placeholder
from ._spec import ALGORITHMS

RULE_IDS = ALGORITHMS["ruleIds"]
MIN_SCAN_LENGTH: int = ALGORITHMS["text"]["minScanLength"]
SYNC_LIMITS = ALGORITHMS["sync"]
STRICT_LIMITS = ALGORITHMS["strict"]
FULL_LIMITS = ALGORITHMS["full"]


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


def _window_hits(units: str) -> list[Hit]:
    """The full-tier rules over `units` (already capped), in overlapping windows when longer than one."""
    window = FULL_LIMITS["scanWindow"]
    if len(units) <= window:
        return detect_full_rules(units)
    stride = window - FULL_LIMITS["scanOverlap"]
    found: list[Hit] = []
    offset = 0
    while offset < len(units):
        window_end = min(offset + window, len(units))
        for rule_id, start, end in detect_full_rules(units[offset:window_end]):
            found.append((rule_id, start + offset, end + offset))
        if window_end >= len(units):
            break
        offset += stride
    return merge_hits(found)


def detect_full(units: str) -> list[Hit]:
    """The merged hits of the full tier (SPEC 4.17): the full-tier rules over the first `scanCap` units, then
    the standard rules over the whole text; on an equal start the full-tier rule's id wins."""
    if len(units) < MIN_SCAN_LENGTH:
        return []
    cap = FULL_LIMITS["scanCap"]
    scanned = units if len(units) <= cap else units[:cap]
    return merge_hits([*_window_hits(scanned), *detect(units)])


def _error_text() -> tuple[str, list[Hit]]:
    rule_id = RULE_IDS["error"]
    return build_read_placeholder(rule_id), [(rule_id, 0, 0)]


def scan_full_compat(units: str) -> tuple[str, list[Hit], str | None]:
    """SPEC 9.4 `compat`: a failure of the full-tier rules falls back to the standard rules, and if those fail
    too the text is replaced by `[REDACTED:error]`. The third item is the class of that last failure."""
    try:
        hits = detect_full(units)
        return (splice(units, hits) if hits else units), hits, None
    except Exception:
        pass
    try:
        text, hits = scan_units(units)
    except Exception as error:
        return (*_error_text(), type(error).__name__)
    return text, hits, None


def scan_full_strict(units: str) -> tuple[str, list[Hit], str | None]:
    """SPEC 9.4 `strict`: no fallback and no unscanned rest. A failure replaces the whole text; the units
    beyond the scan cap become `[REDACTED:size-limit]` (merged with any hit they touch)."""
    try:
        found = detect_full(units)
        cap = FULL_LIMITS["scanCap"]
        if len(units) > cap:
            found = merge_hits([*found, (RULE_IDS["sizeLimit"], cap, len(units))])
        return (splice(units, found) if found else units), found, None
    except Exception as error:
        return (*_error_text(), type(error).__name__)
