"""UTF-16 code units (SPEC section 1).

The normative unit is the UTF-16 code unit. A Python `str` holds code points, so the package
works on a *unit string*: every code unit is one character (an astral character is a high and a
low surrogate; a lone surrogate is one character). Offsets, caps and windows are unit offsets.
"""

import re

_ASTRAL = re.compile("[\U00010000-\U0010ffff]")
_SURROGATE_PAIR = re.compile("[\ud800-\udbff][\udc00-\udfff]")


def _split_astral(match: re.Match[str]) -> str:
    offset = ord(match.group()) - 0x10000
    return chr(0xD800 + (offset >> 10)) + chr(0xDC00 + (offset & 0x3FF))


def _join_pair(match: re.Match[str]) -> str:
    high, low = match.group()
    return chr(0x10000 + ((ord(high) - 0xD800) << 10) + (ord(low) - 0xDC00))


def unit_length(text: str) -> int:
    """The length of `text` in UTF-16 code units, without building the unit string."""
    return len(text) if text.isascii() else len(text.encode("utf-16-le", "surrogatepass")) // 2


def to_units(text: str) -> str:
    """The text with every astral character written as its two surrogate units."""
    if _ASTRAL.search(text) is None:
        return text
    return _ASTRAL.sub(_split_astral, text)


def from_units(units: str) -> str:
    """The unit string as a normal `str`: a high and a low surrogate next to each other are one character."""
    if _SURROGATE_PAIR.search(units) is None:
        return units
    return _SURROGATE_PAIR.sub(_join_pair, units)
