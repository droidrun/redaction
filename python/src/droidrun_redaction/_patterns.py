"""Compiling spec patterns and classes, and the small text helpers every rule kind shares."""

import re
from collections.abc import Callable

from ._spec import expand_pattern

Range = tuple[int, int]
CharTest = Callable[[str], bool]

_LOWER_TABLE = {code: code + 32 for code in range(ord("A"), ord("Z") + 1)}
_LOWER_TABLE[0x212A] = ord("k")


def compile_pattern(template: str) -> re.Pattern[str]:
    """A spec pattern, expanded and compiled the way the spec says (SPEC section 2): ASCII mode."""
    return re.compile(expand_pattern(template), re.ASCII)


def char_test(class_pattern: str) -> CharTest:
    """A test for one unit against a single-class spec pattern."""
    unit_class = compile_pattern(class_pattern)
    known: dict[str, bool] = {}

    def test(unit: str) -> bool:
        cached = known.get(unit)
        if cached is None:
            cached = unit_class.fullmatch(unit) is not None
            known[unit] = cached
        return cached

    return test


def contains_test(class_pattern: str) -> Callable[[str], bool]:
    """A test for "the class matches somewhere in the string"."""
    unit_class = compile_pattern(class_pattern)
    return lambda text: unit_class.search(text) is not None


def run_pattern(class_pattern: str, negate: bool = False) -> re.Pattern[str]:
    """A pattern for the longest run of units in the class (or, negated, outside it)."""
    unit = expand_pattern(class_pattern)
    if negate:
        return re.compile(f"(?:(?!{unit})[\\s\\S])*", re.ASCII)
    return re.compile(f"(?:{unit})*", re.ASCII)


def run_end(run: re.Pattern[str], text: str, start: int, limit: int | None = None) -> int:
    """End of the run that starts at `start`, at most `limit` units long."""
    stop = len(text) if limit is None else min(len(text), start + limit)
    if start >= stop:
        return start
    found = run.match(text, start, stop)
    return start if found is None else found.end()


def fold_lower(text: str) -> str:
    """The spec's `lower`: A-Z to a-z and U+212A (KELVIN SIGN) to `k`; nothing else changes."""
    return text.translate(_LOWER_TABLE)


def search_from(pattern: re.Pattern[str], text: str, position: int) -> re.Match[str] | None:
    """The next match at or after `position`, with the text before it still visible to `\\b`."""
    if position > len(text):
        return None
    return pattern.search(text, position)
