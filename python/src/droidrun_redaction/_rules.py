"""The rule kinds of the standard tier (SPEC section 4), one interpreter per kind.

Each `prepare_*` takes a rule of the spec pipeline, compiles what it needs once and returns a
scanner: a function from a unit string to the ranges the rule finds, in the order of its kind.
"""

import re
from collections.abc import Callable
from typing import Any

from ._evidence import has_value_evidence, is_doc_placeholder, is_trivial_value
from ._keys import is_secret_key_name
from ._patterns import (
    Range,
    char_test,
    compile_pattern,
    contains_test,
    fold_lower,
    run_end,
    run_pattern,
    search_from,
)
from ._placeholder import is_placeholder_value
from ._runs import (
    guarded_run_end,
    label_start,
    percent_decode,
    run_classes,
    trim_query_value,
)

Scanner = Callable[[str], list[Range]]


def _group_span(match: re.Match[str], group: int) -> Range | None:
    """The span of a capture group, or None when the group did not take part in the match."""
    span = match.span(group)
    return None if span[0] == -1 else span


def _prepare_filter(rule: dict[str, Any]) -> Callable[[str, Range], bool]:
    has_class = contains_test(rule["requireClass"]) if "requireClass" in rule else None
    literal = rule.get("requireLiteral")
    ignored = frozenset(rule.get("ignoreEquals", ()))
    drops_placeholder = rule.get("dropPlaceholder") is True

    def passes(text: str, span: Range) -> bool:
        start, end = span
        value = text[start:end]
        if has_class is not None and not has_class(value):
            return False
        if literal is not None and literal not in value:
            return False
        if value in ignored:
            return False
        return not (drops_placeholder and is_placeholder_value(text, start, end))

    return passes


def _prepare_guarded(rule: dict[str, Any]) -> Scanner:
    pattern = compile_pattern(rule["pattern"])
    blocks_before = char_test(rule["notBefore"]) if "notBefore" in rule else None
    blocks_after = char_test(rule["notAfter"]) if "notAfter" in rule else None

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        position = 0
        while (match := search_from(pattern, text, position)) is not None:
            start, end = match.span()
            before = text[start - 1] if start > 0 else None
            after = text[end] if end < len(text) else None
            blocked_before = blocks_before is not None and before is not None and blocks_before(before)
            blocked_after = blocks_after is not None and after is not None and blocks_after(after)
            if blocked_before or blocked_after:
                position = start + 1
                continue
            ranges.append((start, end))
            position = match.end()
        return ranges

    return scan


def _prepare_group(rule: dict[str, Any]) -> Scanner:
    pattern = compile_pattern(rule["pattern"])
    group = rule.get("group", 0)

    def scan(text: str) -> list[Range]:
        spans = (_group_span(match, group) for match in pattern.finditer(text))
        return [span for span in spans if span is not None]

    return scan


def prepare_regex(rule: dict[str, Any]) -> Scanner:
    is_guarded = "notBefore" in rule or "notAfter" in rule
    scan = _prepare_guarded(rule) if is_guarded else _prepare_group(rule)
    passes = _prepare_filter(rule)
    return lambda text: [span for span in scan(text) if passes(text, span)]


def prepare_cookie_lines(rule: dict[str, Any]) -> Scanner:
    pattern = compile_pattern(rule["prefix"])
    classes = run_classes(rule)
    passes = _prepare_filter(rule)

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        position = 0
        while (match := search_from(pattern, text, position)) is not None:
            start = match.end()
            end = guarded_run_end(text, start, classes)
            if end == start:
                position = match.start() + 1
                continue
            position = end
            if passes(text, (start, end)):
                ranges.append((start, end))
        return ranges

    return scan


def prepare_dotted_token(rule: dict[str, Any]) -> Scanner:
    lead = rule["lead"]
    separator = rule["separator"]
    minimum = rule["minSegment"]
    segments = rule["segments"]
    segment_run = run_pattern(rule["segmentClass"])
    is_word = char_test(rule["wordClass"])

    def word_at(text: str, at: int) -> bool:
        return 0 <= at < len(text) and is_word(text[at])

    def is_boundary(text: str, at: int) -> bool:
        return word_at(text, at - 1) != word_at(text, at)

    def match_at(text: str, start: int) -> tuple[int | None, int]:
        """(end of the token or None, end of the first segment's run)."""
        position = start + len(lead)
        first_run_end = position
        for segment in range(segments):
            end = run_end(segment_run, text, position)
            if segment == 0:
                first_run_end = end
            length = end - position
            if length < minimum:
                return None, first_run_end
            if segment < segments - 1:
                if text[end : end + 1] != separator:
                    return None, first_run_end
                position = end + 1
                continue
            for take in range(length, minimum - 1, -1):
                if is_boundary(text, position + take):
                    return position + take, first_run_end
        return None, first_run_end

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        search_at = 0
        skip_until = 0
        while (start := text.find(lead, search_at)) != -1:
            search_at = start + 1
            if start < skip_until or not is_boundary(text, start):
                continue
            end, first_run_end = match_at(text, start)
            if end is None:
                skip_until = first_run_end
                continue
            ranges.append((start, end))
            search_at = end
        return ranges

    return scan


def prepare_pem_blocks(rule: dict[str, Any]) -> Scanner:
    header = compile_pattern(rule["header"])
    footer = compile_pattern(rule["footer"])
    marker = rule["footerMarker"]
    body = run_pattern(rule["bodyChar"])
    body_limit = rule["bodyLimit"]

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        covered = 0
        for match in header.finditer(text):
            start = match.start()
            if start < covered:
                continue
            body_start = match.end()
            body_end = run_end(body, text, body_start, body_limit)
            # Only a marker that starts before the end of the body counts, so the search stops where the
            # last such marker would end: a header never scans the rest of the text.
            footer_at = text.find(marker, body_start, body_end + len(marker) - 1)
            found = footer.match(text, footer_at) if footer_at != -1 else None
            covered = found.end() if found is not None else body_end
            ranges.append((start, covered))
        return ranges

    return scan


def _word_ends(text: str, at: int, is_word: Callable[[str], bool]) -> bool:
    return at >= len(text) or not is_word(text[at])


def _prepare_scheme(rule: dict[str, Any]) -> Scanner:
    pattern = compile_pattern(rule["scheme"])
    value_run = run_pattern(rule["valueClass"])
    lower_run = run_pattern(rule["lowerClass"])
    is_upper = char_test(rule["upperClass"])
    is_word = char_test(rule["wordClass"])
    minimum = rule["minValueLength"]

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        position = 0
        while (match := search_from(pattern, text, position)) is not None:
            start = match.end()
            end = run_end(value_run, text, start)
            lower_end = run_end(lower_run, text, start)
            first = text[start : start + 1]
            capitalized_end = (
                run_end(lower_run, text, start + 1) if first != "" and is_upper(first) else start
            )
            is_plain_word = lower_end > start and _word_ends(text, lower_end, is_word)
            is_capitalized = capitalized_end > start + 1 and _word_ends(text, capitalized_end, is_word)
            if end - start < minimum or is_plain_word or is_capitalized:
                position = match.start() + 1
                continue
            ranges.append((start, end))
            position = end
        return ranges

    return scan


def prepare_auth_values(rule: dict[str, Any]) -> Scanner:
    bearer = compile_pattern(rule["bearer"])
    scheme = _prepare_scheme(rule)
    plain_words = frozenset(rule["plainWords"])

    def scan(text: str) -> list[Range]:
        bearer_spans = (_group_span(match, 1) for match in bearer.finditer(text))
        candidates = [span for span in bearer_spans if span is not None] + scheme(text)
        return [
            (start, end)
            for start, end in candidates
            if fold_lower(text[start:end]) not in plain_words and not is_placeholder_value(text, start, end)
        ]

    return scan


def _real_pair_values(text: str, ranges: list[Range]) -> list[Range]:
    """Pair values: not empty, not a placeholder, not a doc mask or stand-in (SPEC 4.7 step 4)."""
    kept: list[Range] = []
    for start, end in ranges:
        if end <= start or is_placeholder_value(text, start, end):
            continue
        value = text[start:end]
        if not is_trivial_value(value) and not is_doc_placeholder(value):
            kept.append((start, end))
    return kept


def prepare_keyword_pairs(rule: dict[str, Any]) -> Scanner:
    pattern = compile_pattern(rule["prefix"])
    classes = run_classes(rule)
    is_ident = char_test(rule["identChar"])
    minimum = rule["minValueLength"]
    window = rule["window"]
    lookback = rule["labelLookback"]

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        position = 0
        while (match := search_from(pattern, text, position)) is not None:
            value_start = match.end()
            value_end = guarded_run_end(text, value_start, classes, window)
            if value_end - value_start < minimum:
                position = match.start() + 1
                continue
            label = label_start(text, match.start(), is_ident, lookback)
            start, end = trim_query_value(text, label, (value_start, value_end))
            accepted = (
                end > start
                and not is_placeholder_value(text, start, end)
                and has_value_evidence(text[start:end])
            )
            if not accepted:
                position = value_start
                continue
            # A value that filled the window runs on to the end of its run (no suffix of a long secret
            # is left behind); only now, so a rejected candidate never rescans it.
            full = guarded_run_end(text, end, classes) if end - start == window else end
            ranges.append((start, full))
            position = max(full, value_start)
        return ranges

    return scan


def _closing_quote(text: str, start: int, quote: str, layers: int, limit: int) -> tuple[int, int] | None:
    """(position of the closing quote, run of backslashes before it) of a value that opened at `start`."""
    position = text.find(quote, start, limit)
    while position != -1:
        run = 0
        while position - run - 1 >= start and text[position - run - 1] == "\\":
            run += 1
        closes = run % 2 == 0 if layers == 0 else run == layers
        if closes:
            return position, run
        position = text.find(quote, position + 1, limit)
    return None


def prepare_quoted_pairs(rule: dict[str, Any]) -> Scanner:
    pattern = compile_pattern(rule["label"])
    value_limit = rule["valueLimit"]

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        position = 0
        while (match := search_from(pattern, text, position)) is not None:
            start = match.end()
            layers = len(match.group(1))
            limit = min(len(text), start + value_limit)
            closing = _closing_quote(text, start, match.group(2), layers, limit)
            if closing is None:
                ranges.append((start, len(text)))
                break
            value_end = closing[0] - closing[1]
            ranges.append((start, value_end))
            position = value_end
        return _real_pair_values(text, ranges)

    return scan


def prepare_unquoted_pairs(rule: dict[str, Any]) -> Scanner:
    pattern = compile_pattern(rule["prefix"])
    classes = run_classes(rule)

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        position = 0
        while (match := search_from(pattern, text, position)) is not None:
            start = match.end()
            end = guarded_run_end(text, start, classes)
            if end == start:
                position = match.start() + 1
                continue
            position = end
            ranges.append(trim_query_value(text, match.start(), (start, end)))
        return _real_pair_values(text, ranges)

    return scan


def prepare_query_values(rule: dict[str, Any]) -> Scanner:
    query_key = compile_pattern(rule["queryKey"])
    not_value_end = run_pattern(rule["valueEnd"], negate=True)
    not_nested_end = run_pattern(rule["nestedEnd"], negate=True)
    query_only = frozenset(rule["queryOnlyKeys"])
    nested_limit = rule["nestedLimit"]
    drops_placeholder = rule.get("dropPlaceholder") is True

    def is_secret_param(key: str) -> bool:
        return is_secret_key_name(key) or fold_lower(key) in query_only

    def has_secret_param(units: str) -> bool:
        return any(is_secret_param(percent_decode(match.group(1))) for match in query_key.finditer(units))

    def scan(text: str) -> list[Range]:
        ranges: list[Range] = []
        budget = rule["decodeBudget"]
        position = 0
        while (match := search_from(query_key, text, position)) is not None:
            value_start = match.end()
            position = value_start
            if is_secret_param(percent_decode(match.group(1))):
                end = run_end(not_value_end, text, value_start)
                if end > value_start:
                    ranges.append((value_start, end))
                position = max(value_start, end)
                continue
            if budget <= 0:
                continue
            end = run_end(not_nested_end, text, value_start, nested_limit)
            budget -= end - value_start
            raw = text[value_start:end]
            if "%" not in raw:
                continue
            decoded = percent_decode(raw)
            if decoded != raw and has_secret_param("?" + decoded):
                ranges.append((value_start, end))
        if not drops_placeholder:
            return ranges
        return [
            (start, end)
            for start, end in ranges
            if end > start and not is_placeholder_value(text, start, end)
        ]

    return scan
