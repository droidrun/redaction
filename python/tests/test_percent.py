"""Percent decoding of URL query values (SPEC 4.9): a malformed sequence leaves the value whole.

Expected values were produced by the TypeScript package (`decodeURIComponent` with the whole-value fallback).
"""

import pytest
from droidrun_redaction import redact_text
from droidrun_redaction._runs import percent_decode
from droidrun_redaction._units import to_units

URL = "https://x.example/cb?"
HIDDEN = "redirect=%3Ftoken%3Dabc12345xyz"
REDACTED_VALUE = "redirect=[REDACTED:key-context]"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain", "plain"),
        ("a+b%20c", "a+b c"),
        ("%41%62", "Ab"),
        ("%C3%A9", "é"),
        ("%F0%9F%98%80", "😀"),
        ("%", "%"),
        ("%4", "%4"),
        ("%zz", "%zz"),
        ("ok%41%FF", "ok%41%FF"),
        ("%C0%80", "%C0%80"),
        ("%ED%A0%80", "%ED%A0%80"),
        ("%F4%90%80%80", "%F4%90%80%80"),
        ("%E2%82", "%E2%82"),
        ("%C3%28", "%C3%28"),
        ("%80", "%80"),
    ],
)
def test_percent_decode(raw, expected):
    assert percent_decode(raw) == to_units(expected)


@pytest.mark.parametrize("tail", ["", "%C3%A9", "%F0%9F%98%80"])
def test_a_well_formed_nested_secret_parameter_is_redacted(tail):
    assert redact_text(f"{URL}{HIDDEN}{tail}", mode="compat").value == f"{URL}{REDACTED_VALUE}"


@pytest.mark.parametrize("tail", ["%FF", "%C0%80", "%ED%A0%80", "%F4%90%80%80", "%E2%82", "%", "%4"])
def test_a_malformed_sequence_leaves_a_nested_secret_parameter_as_it_is(tail):
    text = f"{URL}{HIDDEN}{tail}"
    assert redact_text(text, mode="compat").value == text


def test_a_percent_encoded_parameter_name_is_decoded_before_the_key_check():
    assert (
        redact_text(f"{URL}%74%6F%6Ben=abc12345xyz", mode="compat").value
        == f"{URL}%74%6F%6Ben=[REDACTED:key-context]"
    )


def test_a_malformed_parameter_name_is_not_a_secret_name():
    text = f"{URL}%74%6F%6Ben%FF=abc12345xyz"
    assert redact_text(text, mode="compat").value == text
