"""The letter guard of the full tier (SPEC 5.6): "the code point before a position is not a letter".

The letters are the Unicode 15.0.0 categories Lu, Ll, Lt, Lm and Lo as the table of `algorithms.json`
(never `unicodedata`, whose Unicode version is the interpreter's).
"""

from bisect import bisect_right

from ._spec import ALGORITHMS

_HEX = 16
_ASTRAL_BASE = 0x10000
_SURROGATE_BITS = 10


def _parse_ranges(encoded: str) -> tuple[list[int], list[int]]:
    lows: list[int] = []
    highs: list[int] = []
    for item in encoded.split(","):
        low, _, high = item.partition("-")
        lows.append(int(low, _HEX))
        highs.append(int(high or low, _HEX))
    return lows, highs


_LOWS, _HIGHS = _parse_ranges(ALGORITHMS["letters"]["ranges"])


def is_letter(code_point: int) -> bool:
    """True when the code point is in the table (binary search over the sorted ranges)."""
    index = bisect_right(_LOWS, code_point) - 1
    return index >= 0 and code_point <= _HIGHS[index]


def _code_point_before(units: str, at: int) -> int:
    """The code point that ends at `at`: a surrogate pair is one code point, a lone surrogate is itself."""
    unit = ord(units[at - 1])
    if not 0xDC00 <= unit <= 0xDFFF or at < 2:
        return unit
    lead = ord(units[at - 2])
    if not 0xD800 <= lead <= 0xDBFF:
        return unit
    return _ASTRAL_BASE + ((lead - 0xD800) << _SURROGATE_BITS) + (unit - 0xDC00)


def passes_letter_guard(units: str, start: int) -> bool:
    """False (the start is refused) when the code point before `start` is a letter."""
    return start == 0 or not is_letter(_code_point_before(units, start))
