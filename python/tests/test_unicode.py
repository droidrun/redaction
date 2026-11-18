"""Unit handling (SPEC section 1): whitespace set, case folding, astral characters, lone surrogates, caps.

Expected values were produced by the TypeScript package and are written out here as literals.
"""

import pytest
from droidrun_redaction import is_secret_key_name, redact_json, redact_text
from droidrun_redaction._units import to_units, unit_length

SECRET = "Zq9abcDEF123ghi_x"
PLACEHOLDER = "[REDACTED:generic-keyword]"
SMILE = "\U0001f600"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(f"password: {SECRET}", f"password: {PLACEHOLDER}", id="nbsp after the separator"),
        pytest.param(f"﻿password={SECRET}", f"﻿password={PLACEHOLDER}", id="bom before the keyword"),
        pytest.param(f"password={SECRET} next", f"password={PLACEHOLDER} next", id="u202f ends the value"),
        pytest.param(f"password={SECRET} next", f"password={PLACEHOLDER} next", id="u2028 ends the value"),
        pytest.param(f"password={SECRET}﻿next", f"password={PLACEHOLDER}﻿next", id="bom ends the value"),
    ],
)
def test_whitespace_set_is_the_javascript_one(text, expected):
    assert redact_text(text, mode="compat").value == expected


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(f"passKword={SECRET}", id="kelvin sign inside a keyword"),
        pytest.param(f"paſſword={SECRET}", id="long s inside a keyword"),
        pytest.param(f"İpass={SECRET}", id="dotted capital i before a keyword"),
        pytest.param(f"TOKEN={SECRET}", id="kelvin sign in an upper-case keyword"),
    ],
)
def test_keywords_are_not_case_folded_beyond_ascii(text):
    assert redact_text(text, mode="compat").value == text


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("pİn", True),
        ("pin", True),
        ("TOKEN", False),
        ("paſſ", False),
        ("apiKey", False),
    ],
)
def test_key_name_folding(key, expected):
    assert is_secret_key_name(key) is expected


def test_astral_characters_are_two_units_in_the_minimum_value_length():
    # 3 ASCII characters and 3 astral ones: 6 code points, 9 units; a value needs 8 units.
    result = redact_text(f"password=aB1{SMILE}{SMILE}{SMILE}", mode="compat")
    assert result.value == f"password={PLACEHOLDER}"


def test_astral_characters_inside_a_value_are_redacted_with_it():
    assert redact_text(f"password=Zq9abc{SMILE}DEF123ghi_x", mode="compat").value == f"password={PLACEHOLDER}"


def test_astral_characters_outside_a_range_are_copied():
    text = f"{SMILE}{SMILE} password={SECRET}"
    assert redact_text(text, mode="compat").value == f"{SMILE}{SMILE} password={PLACEHOLDER}"


def test_a_jwt_followed_by_an_astral_character_keeps_it():
    text = f"eyJabcdefghijk.eyJabcdefghijk.abcdefghijk{SMILE}"
    assert redact_text(text, mode="compat").value == f"[REDACTED:jwt]{SMILE}"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            f"\ud800 password={SECRET}", f"\ud800 password={PLACEHOLDER}", id="lone high surrogate before"
        ),
        pytest.param(
            f"password={SECRET} \udc00", f"password={PLACEHOLDER} \udc00", id="lone low surrogate after"
        ),
        pytest.param(
            "password=Zq9abc\ud800DEF123ghi_x", f"password={PLACEHOLDER}", id="lone surrogate inside a value"
        ),
    ],
)
def test_lone_surrogates_are_single_units_and_survive(text, expected):
    assert redact_text(text, mode="compat").value == expected


def test_a_cap_counts_utf16_units_for_text():
    text = SMILE * 4
    assert redact_text(text, mode="compat", max_chars=7).value == "[REDACTED:size-limit]"
    assert redact_text(text, mode="compat", max_chars=8).value == text


def test_a_cap_counts_utf16_units_for_a_json_leaf():
    assert redact_json({"a": SMILE * 4}, mode="compat", max_chars=7).value == {"a": "[REDACTED:size-limit]"}
    assert redact_json({"a": SMILE * 4}, mode="compat", max_chars=8).value == {"a": SMILE * 4}


def test_a_strict_key_counts_utf16_units_against_the_budget():
    key = SMILE * 4
    assert redact_json({key: "x"}, mode="strict", max_chars=8).value == {key: "[REDACTED:size-limit]"}
    assert redact_json({key: "x"}, mode="strict", max_chars=9).value == {key: "x"}


def test_keys_keep_the_ecmascript_order():
    value = {"b": "x", "10": "y", "2": "z", "a": "w", "01": "q", "4294967295": "r", "4294967294": "s"}
    keys = list(redact_json(value, mode="compat").value)
    assert keys == ["2", "10", "4294967294", "b", "a", "01", "4294967295"]


def test_a_key_that_holds_a_secret_is_redacted_and_colliding_keys_keep_both_values():
    value = {"password=Zq9abcDEF123ghi_x": 1, "password=Zq9abcDEF123ghi_y": 2}
    assert redact_json(value, mode="compat").value == {
        f"password={PLACEHOLDER}": "[REDACTED:key-context]",
        "password=[REDACTED:generic-keyword#2]": "[REDACTED:key-context]",
    }


def test_numbers_equal_the_typescript_output_as_doubles():
    value = {"n": 9007199254740993, "pin": 12, "max_tokens": 5, "f": 1.0, "neg": -0.0}
    out = redact_json(value, mode="compat").value
    assert list(out) == ["n", "pin", "max_tokens", "f", "neg"]
    assert float(out["n"]) == 9007199254740992.0
    assert out["pin"] == "[REDACTED:key-context]"
    assert (out["max_tokens"], out["f"], out["neg"]) == (5, 1.0, 0.0)


@pytest.mark.parametrize("mode", ["strict", "compat"])
def test_an_integer_that_is_not_replaced_comes_back_exactly(mode):
    value = {"big": 9007199254740993, "huge": 10**400, "neg": -(2**70), "list": [2**64 + 1]}
    out = redact_json(value, mode=mode).value
    assert out == value
    assert all(type(item) is int for item in (out["big"], out["huge"], out["neg"], out["list"][0]))


@pytest.mark.parametrize("mode", ["strict", "compat"])
def test_an_integer_under_a_secret_key_is_still_replaced(mode):
    assert redact_json({"pin": 10**400}, mode=mode).value == {"pin": "[REDACTED:key-context]"}


@pytest.mark.parametrize(
    ("text", "units"),
    [("", 0), ("abc", 3), ("é", 1), (SMILE, 2), (SMILE * 3 + "a", 7), ("\ud800", 1), ("𝐀", 2)],
)
def test_unit_length_counts_utf16_units_without_converting(text, units):
    assert unit_length(text) == units
    assert unit_length(text) == len(to_units(text))
