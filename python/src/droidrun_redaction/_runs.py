"""Shared algorithms of SPEC section 5 and the query-value helpers of 4.9: runs, labels, percent decoding."""

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ._patterns import CharTest, Range, char_test, fold_lower, run_end, run_pattern
from ._units import to_units


@dataclass(frozen=True)
class RunClasses:
    plain: re.Pattern[str]
    stop: CharTest


def run_classes(rule: dict[str, Any]) -> RunClasses:
    return RunClasses(plain=run_pattern(rule["plainChar"]), stop=char_test(rule["escapeStop"]))


def guarded_run_end(text: str, start: int, classes: RunClasses, limit: int | None = None) -> int:
    """End of the run of plain units and of backslashes that do not begin an escape (SPEC 5.1)."""
    stop = len(text) if limit is None else min(len(text), start + limit)
    position = start
    while position < stop:
        position = run_end(classes.plain, text, position, stop - position)
        if position >= stop or text[position] != "\\":
            return position
        follower = text[position + 1 : position + 2]
        if follower != "" and classes.stop(follower):
            return position
        position += 1
    return position


def label_start(text: str, keyword_start: int, is_ident: Callable[[str], bool], lookback: int) -> int:
    """Start of the identifier that holds the keyword at `keyword_start` (SPEC 5.2)."""
    start = keyword_start
    while start > 0 and keyword_start - start < lookback and is_ident(text[start - 1]):
        start -= 1
    return start


def is_ascii_letter(unit: str) -> bool:
    return "a" <= unit <= "z" or "A" <= unit <= "Z"


def word_before(text: str, at: int, is_gap: Callable[[str], bool]) -> str:
    """The lower-case ASCII letters that end just before `at`, after the units of `is_gap` there (SPEC 4.1)."""
    end = label_start(text, at, is_gap, len(text))
    start = label_start(text, end, is_ascii_letter, len(text))
    return fold_lower(text[start:end])


def remembered_run_end(text: str, classes: RunClasses) -> Callable[[int], int]:
    """`guarded_run_end` from a start, with the run last measured remembered (SPEC 4.18 step 2): the end of a
    run is the same from every start inside it, so a text of many pairs in one long run is measured once."""
    low = 0
    high = 0

    def end_of(start: int) -> int:
        nonlocal low, high
        if low <= start < high:
            return high
        low = start
        high = guarded_run_end(text, start, classes)
        return high

    return end_of


def remembered_ampersand(text: str) -> Callable[[int], int]:
    """The first `&` at or after `start` (or -1), remembered: `start` only grows within one scan."""
    unknown = -2
    found = unknown

    def next_at(start: int) -> int:
        nonlocal found
        if found == unknown or (found != -1 and found < start):
            found = text.find("&", start)
        return found

    return next_at


def trim_query_value(text: str, label: int, value: Range) -> Range:
    """Inside a URL query a value ends at the next `&` (SPEC 5.3)."""
    before = text[label - 1 : label] if label > 0 else ""
    if before not in ("?", "&"):
        return value
    ampersand = text.find("&", value[0], value[1])
    if ampersand != -1:
        return (value[0], ampersand)
    return value


_ESCAPE_RUN = re.compile("(?:%[0-9a-fA-F]{2})+", re.ASCII)


def percent_decode(units: str) -> str:
    """`decodeURIComponent` on a unit string, or the string itself when it holds a malformed escape."""
    if "%" not in units:
        return units
    parts: list[str] = []
    position = 0
    for run in _ESCAPE_RUN.finditer(units):
        literal = units[position : run.start()]
        if "%" in literal:
            return units
        try:
            decoded = bytes.fromhex(run.group().replace("%", "")).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return units
        parts.extend((literal, to_units(decoded)))
        position = run.end()
    tail = units[position:]
    if "%" in tail:
        return units
    parts.append(tail)
    return "".join(parts)
