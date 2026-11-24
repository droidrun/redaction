"""Scanning one text (SPEC 9.1) and one object key (SPEC section 8) with the standard rules."""

from collections.abc import Callable

from ._detect import Detect, Hit, detect, detect_full_rules, merge_hits, scan_floor, splice
from ._placeholder import build_read_placeholder
from ._spec import ALGORITHMS
from ._units import to_units

RULE_IDS = ALGORITHMS["ruleIds"]
SYNC_LIMITS = ALGORITHMS["sync"]
STRICT_LIMITS = ALGORITHMS["strict"]
FULL_LIMITS = ALGORITHMS["full"]


def scan_units(units: str, options: Detect) -> tuple[str, list[Hit]]:
    """The unit string with its secrets replaced, and the hits (no length cap here)."""
    hits = detect(units, options)
    return splice(units, hits), hits


def tally(counts: dict[str, int], hits: list[Hit]) -> None:
    """Add one to the count of each hit's rule (ranges are dropped here: they reveal lengths)."""
    for rule_id, _start, _end in hits:
        counts[rule_id] = counts.get(rule_id, 0) + 1


def oversize_text(length: int) -> tuple[str, list[Hit]]:
    """What a text of `length` units over the cap becomes (SPEC 9.1): the size-limit placeholder."""
    rule_id = RULE_IDS["sizeLimit"]
    return build_read_placeholder(rule_id), [(rule_id, 0, length)]


Scan = Callable[[str, Detect], tuple[str, list[Hit], str | None]]


def scan_standard(units: str, options: Detect) -> tuple[str, list[Hit], str | None]:
    """`scan_units` in the shape of the full-tier scans: no error class."""
    text, hits = scan_units(units, options)
    return text, hits, None


def scan_capped(
    text: str, limit: int | None, scan: Scan, options: Detect
) -> tuple[str, list[Hit], str | None]:
    """SPEC 9.1: a text over `limit` UTF-16 units (None: no limit) is replaced whole, else `scan` runs.

    A text has at least as many units as characters, so a text over the limit by characters is over it by
    units: it is replaced without being converted. Any other text is converted, and its units are checked.
    """
    if limit is not None and len(text) > limit:
        placeholder, hits = oversize_text(len(text))
        return placeholder, hits, None
    units = to_units(text)
    if limit is not None and len(units) > limit:
        placeholder, hits = oversize_text(len(units))
        return placeholder, hits, None
    return scan(units, options)


def redact_key(key_units: str, scan: Scan, options: Detect) -> tuple[str, list[Hit], str | None]:
    """The key with its secrets replaced by `scan` (a key over `maxKeyChars` is left as it is), the hits, and
    the class of the scan's failure."""
    if is_overlong_key(key_units):
        return key_units, [], None
    return scan(key_units, options)


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


def detect_full(units: str, options: Detect) -> list[Hit]:
    """The merged hits of the full tier (SPEC 4.17): the full-tier rules over the first `scanCap` units, then
    the standard rules of `options` over the whole text; on an equal start the full-tier rule's id wins."""
    if len(units) < scan_floor(options):
        return []
    cap = FULL_LIMITS["scanCap"]
    scanned = units if len(units) <= cap else units[:cap]
    return merge_hits([*_window_hits(scanned), *detect(units, options)])


def _error_text() -> tuple[str, list[Hit]]:
    rule_id = RULE_IDS["error"]
    return build_read_placeholder(rule_id), [(rule_id, 0, 0)]


def scan_full_compat(units: str, options: Detect) -> tuple[str, list[Hit], str | None]:
    """SPEC 9.4 `compat`: a failure of the full-tier rules falls back to the standard rules, and if those fail
    too the text is replaced by `[REDACTED:error]`. The third item is the class of the full rules' failure
    (None when they did not fail): the result is then the standard rules', or the error placeholder."""
    try:
        hits = detect_full(units, options)
        return (splice(units, hits) if hits else units), hits, None
    except Exception as failure:
        error = type(failure).__name__
    try:
        text, hits = scan_units(units, options)
    except Exception:
        return (*_error_text(), error)
    return text, hits, error


def scan_full_strict(units: str, options: Detect) -> tuple[str, list[Hit], str | None]:
    """SPEC 9.4 `strict`: no fallback and no unscanned rest. A failure replaces the whole text; the units
    beyond the scan cap become `[REDACTED:size-limit]` (merged with any hit they touch)."""
    try:
        found = detect_full(units, options)
        cap = FULL_LIMITS["scanCap"]
        if len(units) > cap:
            found = merge_hits([*found, (RULE_IDS["sizeLimit"], cap, len(units))])
        return (splice(units, found) if found else units), found, None
    except Exception as error:
        return (*_error_text(), type(error).__name__)
