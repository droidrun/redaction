"""Placeholders (SPEC section 7): the format, the grammar, the idempotence guard."""

from collections import deque

from ._patterns import compile_pattern
from ._spec import ALGORITHMS, RULES

_FORMAT = ALGORITHMS["placeholder"]
_PLACEHOLDER = compile_pattern(RULES["patterns"]["placeholder"])

# The text every placeholder starts with, without the rule separator: what a redacted key still holds.
PLACEHOLDER_MARK: str = _FORMAT["open"].removesuffix(":")


def shorten_rule_id(rule_id: str) -> str:
    """The rule id without its `stripPrefixes` noise (each prefix at most once, in order)."""
    short = rule_id
    for prefix in _FORMAT["stripPrefixes"]:
        short = short.removeprefix(prefix)
    return short


def build_read_placeholder(rule_id: str) -> str:
    """`[REDACTED:<rule id>]`: no unit of the secret appears in it."""
    return f"{_FORMAT['open']}{shorten_rule_id(rule_id)}{_FORMAT['close']}"


def is_whole_placeholder(text: str) -> bool:
    """True when `text` is exactly one placeholder (a full match: a final line terminator breaks it)."""
    return _PLACEHOLDER.fullmatch(text) is not None


def placeholder_end_at(text: str, start: int) -> int:
    """End of the placeholder that starts exactly at `start`, or -1."""
    found = _PLACEHOLDER.match(text, start)
    return -1 if found is None else found.end()


def is_placeholder_value(text: str, start: int, end: int) -> bool:
    """True when a placeholder starts at `start` and reaches at least `end` (the idempotence guard)."""
    placeholder_end = placeholder_end_at(text, start)
    return placeholder_end != -1 and placeholder_end >= end


# The mark that starts a number inside a placeholder (`[REDACTED:npm#2]`, SPEC 7, numbered form).
NUMBER_MARK = "#"


def _ends_with_number(rule: str) -> bool:
    """True when the rule part ends with `#<digits>` (it is itself numbered)."""
    at = rule.rfind(NUMBER_MARK)
    if at == -1 or at == len(rule) - len(NUMBER_MARK):
        return False
    return rule[at + len(NUMBER_MARK) :].isascii() and rule[at + len(NUMBER_MARK) :].isdigit()


def number_slot(key: str) -> int | None:
    """Where a number goes in a key (SPEC 8, key collisions): the index of the `]` of its last placeholder,
    when that is exactly `[REDACTED:<rule>]` with a rule that has no `:suffix` and is not itself numbered.
    Otherwise None (no placeholder, a `:suffix`, the bare `[REDACTED]`, an already numbered rule)."""
    last = next(iter(deque(_PLACEHOLDER.finditer(key), maxlen=1)), None)
    if last is None or not key.startswith(_FORMAT["open"], last.start()):
        return None
    rule = key[last.start() + len(_FORMAT["open"]) : last.end() - len(_FORMAT["close"])]
    if ":" in rule or _ends_with_number(rule):
        return None
    return last.end() - len(_FORMAT["close"])


def literal_segments(text: str) -> list[str]:
    """The text between placeholders: one element more than there are placeholders, empty ones kept."""
    return _PLACEHOLDER.split(text)
