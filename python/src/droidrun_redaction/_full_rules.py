"""The rule kinds only the full tier uses (SPEC 4.11 to 4.15): `token`, `dash-chain`, `sendgrid-key`,
`pem-key` and `credential-uri`. The kind `regex` is the standard one (`_rules.prepare_regex`).

Each `prepare_*` takes a rule of `full` in the spec, compiles what it needs once and returns a scanner: a
function from a unit string to the ranges the rule finds, in the order of its kind.
"""

import itertools
import re
from collections.abc import Callable, Iterator
from typing import Any

from ._base64_json import is_base64_json
from ._letters import passes_letter_guard
from ._patterns import (
    Range,
    char_test,
    compile_pattern,
    fold_lower,
    run_end,
    run_pattern,
)
from ._rules import Scanner
from ._scan_support import RunEnd, cached_run_end, next_start_of
from ._spec import SpecError

_FAIL = -1
_CHECKS: dict[str, Callable[[str], bool]] = {"base64-json": is_base64_json}


class _Context:
    """One scan of one text: the text and the run memory of each variable-run part (made on first use)."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.memo: dict[int, RunEnd] = {}


Continue = Callable[[int], int]
Step = Callable[[_Context, int, Continue], int]


def _literal_step(literal: str) -> Step:
    def step(context: _Context, position: int, rest: Continue) -> int:
        return rest(position + len(literal)) if context.text.startswith(literal, position) else _FAIL

    return step


def _alternative_step(literals: list[str]) -> Step:
    def step(context: _Context, position: int, rest: Continue) -> int:
        for literal in literals:
            if context.text.startswith(literal, position):
                return rest(position + len(literal))
        return _FAIL

    return step


def _fixed_run_step(run: re.Pattern[str], count: int) -> Step:
    """Exactly `count` units of the class."""

    def step(context: _Context, position: int, rest: Continue) -> int:
        if position + count > len(context.text):
            return _FAIL
        if run_end(run, context.text, position, count) != position + count:
            return _FAIL
        return rest(position + count)

    return step


def _maximal_run_step(part: dict[str, Any], memory_id: int) -> Step:
    """The maximal run; `tails` (the first one the run ends with) are part of the run but not counted."""
    run = run_pattern(part["runClass"])
    minimum, maximum = part["min"], part["max"]
    tails = part.get("tails")

    def step(context: _Context, position: int, rest: Continue) -> int:
        end_of = context.memo.get(memory_id)
        if end_of is None:
            end_of = context.memo[memory_id] = cached_run_end(context.text, run)
        end = end_of(position)
        length = end - position
        tail_length = 0
        if tails is not None:
            tail = next(
                (t for t in tails if length >= len(t) and context.text.startswith(t, end - len(t))), None
            )
            if tail is None:
                return _FAIL
            tail_length = len(tail)
        counted = length - tail_length
        return _FAIL if counted < minimum or counted > maximum else rest(end)

    return step


def _sequence(steps: list[Step], index: int, context: _Context, position: int, rest: Continue) -> int:
    if index == len(steps):
        return rest(position)
    return steps[index](context, position, lambda after: _sequence(steps, index + 1, context, after, rest))


def _optional_step(inner: list[Step]) -> Step:
    def step(context: _Context, position: int, rest: Continue) -> int:
        with_group = _sequence(inner, 0, context, position, rest)
        return with_group if with_group != _FAIL else rest(position)

    return step


def _compile_part(part: dict[str, Any], memory_ids: Iterator[int]) -> Step:
    """`memory_ids` numbers the variable-run parts of one rule, in the order they are compiled."""
    if "lit" in part:
        return _literal_step(part["lit"])
    if "alt" in part:
        return _alternative_step(part["alt"])
    if "opt" in part:
        return _optional_step([_compile_part(inner, memory_ids) for inner in part["opt"]])
    if part["min"] == part["max"] and "tails" not in part:
        return _fixed_run_step(run_pattern(part["runClass"]), part["min"])
    return _maximal_run_step(part, next(memory_ids))


def _first_literals(first: dict[str, Any]) -> list[str]:
    if "lit" in first:
        return [first["lit"]]
    if "alt" in first:
        return list(first["alt"])
    raise SpecError("redaction spec token shape does not start with a literal")


def prepare_token(rule: dict[str, Any]) -> Scanner:
    memory_ids = itertools.count()
    steps = [_compile_part(part, memory_ids) for part in rule["parts"]]
    starts = _first_literals(rule["parts"][0])
    blocks_after = char_test(rule["notAfter"]) if "notAfter" in rule else None
    has_letter_guard = rule.get("letterGuard") is True
    check_name = rule.get("check")
    check = _CHECKS.get(check_name) if check_name is not None else None
    if check_name is not None and check is None:
        raise SpecError("redaction spec names an unknown check")
    check_from = rule.get("checkFrom", 0)

    def scan(text: str) -> list[Range]:
        context = _Context(text)

        def end_guard(position: int) -> int:
            if blocks_after is not None and position < len(text) and blocks_after(text[position]):
                return _FAIL
            return position

        next_start = next_start_of(text, starts)
        ranges: list[Range] = []
        search_at = 0
        start = next_start(search_at)
        while start != -1:
            search_at = start + 1
            if not has_letter_guard or passes_letter_guard(text, start):
                end = _sequence(steps, 0, context, start, end_guard)
                if end != _FAIL:
                    search_at = end
                    if check is None or check(text[start + check_from : end]):
                        ranges.append((start, end))
            start = next_start(search_at)
        return ranges

    return scan


def prepare_dash_chain(rule: dict[str, Any]) -> Scanner:
    segment_run = run_pattern(rule["segmentClass"])
    is_word = char_test(rule["wordClass"])
    leads = rule["leads"]
    separator = rule["separator"]
    max_segment = rule["maxSegment"]
    min_segments = rule["minSegments"]

    def scan(text: str) -> list[Range]:
        end_of = cached_run_end(text, segment_run)

        def word_at(at: int) -> bool:
            return 0 <= at < len(text) and is_word(text[at])

        def match_end(after_lead: int) -> int:
            """End of the last run that may end the token, or -1."""
            ends: list[int] = []
            position = after_lead
            while True:
                end = end_of(position)
                length = end - position
                if length < 1 or length > max_segment:
                    break
                ends.append(end)
                if text[end : end + 1] != separator:
                    break
                position = end + 1
            used = len(ends) if ends and not word_at(ends[-1]) else len(ends) - 1
            return ends[used - 1] if used >= min_segments else -1

        next_start = next_start_of(text, leads)
        ranges: list[Range] = []
        search_at = 0
        start = next_start(search_at)
        while start != -1:
            search_at = start + 1
            if not word_at(start - 1):
                lead = next(item for item in leads if text.startswith(item, start))
                after_lead = start + len(lead)
                if text[after_lead : after_lead + 1] == separator:
                    end = match_end(after_lead + 1)
                    if end != -1:
                        ranges.append((start, end))
                        search_at = end
            start = next_start(search_at)
        return ranges

    return scan


def prepare_sendgrid_key(rule: dict[str, Any]) -> Scanner:
    word_run = run_pattern(rule["wordClass"])
    lead = rule["lead"]
    separator = rule["separator"]
    dash = rule["dash"]
    max_segment = rule["maxSegment"]
    key_length = rule["length"]

    def scan(text: str) -> list[Range]:
        end_of = cached_run_end(text, word_run)

        def tail_end(position: int) -> int:
            """End of the match the expression finds after the second separator at `position`, or -1."""
            end = end_of(position)
            length = end - position
            if length == 0:
                return -1
            if length <= max_segment and text[end : end + 1] == dash:
                after = end_of(end + 1)
                if 1 <= after - (end + 1) <= max_segment:
                    return after
            return end if 2 <= length <= max_segment * 2 else -1

        def match_end(start: int) -> int:
            after_lead = start + len(lead)
            first_end = end_of(after_lead)
            first_length = first_end - after_lead
            if not 1 <= first_length <= max_segment or text[first_end : first_end + 1] != separator:
                return -1
            return tail_end(first_end + 1)

        next_start = next_start_of(text, [lead])
        ranges: list[Range] = []
        search_at = 0
        start = next_start(search_at)
        while start != -1:
            search_at = start + 1
            if passes_letter_guard(text, start):
                end = match_end(start)
                if end != -1:
                    search_at = end
                    if end - start == key_length:
                        ranges.append((start, end))
            start = next_start(search_at)
        return ranges

    return scan


def _has_body_length(rule: dict[str, Any], length: int, leading: bool, trailing: bool) -> bool:
    """True when a body of `length` units can be chosen, with or without the line feed after the header
    (`leading`) and before the footer (`trailing`)."""
    options = [length]
    if leading:
        options.append(length - 1)
    if trailing:
        options.append(length - 1)
    if leading and trailing and length >= 2:
        options.append(length - 2)
    return any(rule["minBody"] <= option <= rule["maxBody"] for option in options)


def _stripped(body: str, is_strip: Callable[[str], bool], literal: str) -> str:
    """The body without whitespace and without the two-unit text `\\n`."""
    kept: list[str] = []
    at = 0
    while at < len(body):
        if is_strip(body[at]):
            at += 1
        elif body.startswith(literal, at):
            at += len(literal)
        else:
            kept.append(body[at])
            at += 1
    return "".join(kept)


def prepare_pem_key(rule: dict[str, Any]) -> Scanner:
    header = compile_pattern(rule["header"])
    footer = compile_pattern(rule["footer"])
    body_run = run_pattern(rule["bodyClass"])
    content_run = run_pattern(rule["contentClass"])
    pad_run = run_pattern(rule["padChar"])
    is_strip = char_test(rule["stripClass"])
    newline = rule["newline"]
    strip_literal = rule["stripLiteral"]
    magic = tuple(rule["magic"])

    def is_key_content(content: str) -> bool:
        """`[contentClass]+` then `padChar*`, at least `minContent` units, starting with one of `magic`."""
        content_end = run_end(content_run, content, 0)
        if content_end == 0 or run_end(pad_run, content, content_end) != len(content):
            return False
        return len(content) >= rule["minContent"] and content.startswith(magic)

    def scan(text: str) -> list[Range]:
        end_of = cached_run_end(text, body_run)
        ranges: list[Range] = []
        position = 0
        while (found := header.search(text, position)) is not None:
            start = found.start()
            body_start = found.end()
            position = start + 1
            body_end = end_of(body_start)
            length = body_end - body_start
            leading = text.startswith(newline, body_start)
            trailing = length > 0 and text.startswith(newline, body_end - 1)
            if not _has_body_length(rule, length, leading, trailing):
                continue
            closing = footer.match(text, body_end)
            if closing is None:
                continue
            if not is_key_content(_stripped(text[body_start:body_end], is_strip, strip_literal)):
                continue
            ranges.append((start, closing.end()))
            position = closing.end()
        return ranges

    return scan


def _contains_any(value: str, items: list[str]) -> bool:
    folded = fold_lower(value)
    return any(fold_lower(item) in folded for item in items)


def _is_repeated(value: str, run_length: int) -> bool:
    """At least `run_length` units, all the same unit."""
    return len(value) >= run_length and value == value[0] * len(value)


def prepare_credential_uri(rule: dict[str, Any]) -> Scanner:
    pattern = compile_pattern(rule["pattern"])
    variables = [compile_pattern(source) for source in rule.get("variablePatterns", [])]
    user_min = rule.get("userMin", 0)
    password_min = rule["passwordMin"]
    user_ignore = rule.get("userIgnoreContains", [])
    password_ignore = rule.get("passwordIgnoreContains", [])
    password_equals = [fold_lower(item) for item in rule.get("passwordIgnoreEquals", [])]
    user_equals_password = rule.get("userEqualsPassword") is True
    repeat_run = rule["repeatRun"]

    def is_real_user(user: str) -> bool:
        return len(user) >= user_min and not _contains_any(user, user_ignore)

    def is_real_password(user: str, password: str) -> bool:
        if user_equals_password and user == password:
            return False
        if len(password) < password_min:
            return False
        if any(variable.search(password) is not None for variable in variables):
            return False
        if _contains_any(password, password_ignore) or fold_lower(password) in password_equals:
            return False
        return not _is_repeated(password, repeat_run)

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        for match in pattern.finditer(text):
            user, password = match.group(1), match.group(2)
            if not user or not password:
                continue
            if is_real_user(user) and is_real_password(user, password):
                ranges.append(match.span())
        return ranges

    return scan
