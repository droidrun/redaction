"""Strict mode never returns a value it did not scan (SPEC 9.3).

Covers caps, depth, nodes, skip keys and values outside the JSON model.
"""

import math

import pytest
from droidrun_redaction import redact_json, redact_text

TOKEN = "ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234"
SIZE_LIMIT = "[REDACTED:size-limit]"
FAILED = "[REDACTED:redaction-failed]"


def test_text_over_the_cap_is_replaced_whole():
    result = redact_text("a" * 11, max_chars=10)
    assert (result.value, result.hits, result.error) == (SIZE_LIMIT, (("size-limit", 1),), None)


def test_default_mode_is_strict():
    assert redact_json({"id": TOKEN}).value == {"id": "[REDACTED:github]"}
    assert redact_json({"id": TOKEN}, mode="compat").value == {"id": TOKEN}


def test_a_string_under_a_skip_key_is_scanned_but_not_replaced_by_the_key_context():
    value = {"password": {"id": "plain", "type": "x password=Zq9abcDEF123ghi_x"}}
    expected = {"password": {"id": "plain", "type": "x password=[REDACTED:generic-keyword]"}}
    assert redact_json(value).value == expected


def test_numbers_and_booleans_under_skip_keys_are_unchanged():
    assert redact_json({"id": 7, "type": True, "password": {"id": None}}).value == {
        "id": 7,
        "type": True,
        "password": {"id": None},
    }


def test_custom_skip_keys_replace_the_default_ones():
    value = {"id": TOKEN, "kind": TOKEN}
    assert redact_json(value, skip_keys=["kind"]).value == {
        "id": "[REDACTED:github]",
        "kind": "[REDACTED:github]",
    }
    assert redact_json(value, skip_keys=["kind"], mode="compat").value == {
        "id": "[REDACTED:github]",
        "kind": TOKEN,
    }


def test_depth_limit_replaces_the_deeper_container():
    value = {"a": {"b": {"c": "x"}}}
    assert redact_json(value, max_depth=2).value == {"a": {"b": "[REDACTED:depth-limit]"}}


def test_nodes_exhausted_in_an_array_collapses_the_rest():
    assert redact_json([1, 2, 3, 4, 5], max_nodes=3).value == [1, 2, SIZE_LIMIT]


def test_nodes_exhausted_in_an_object_collapses_the_rest_under_one_key():
    value = {"a": 1, "b": 2, "c": 3, "d": 4}
    assert redact_json(value, max_nodes=3).value == {"a": 1, "b": 2, SIZE_LIMIT: SIZE_LIMIT}


def test_the_raw_key_of_an_unscanned_entry_is_not_returned():
    secret_key = "password=Zq9abcDEF123ghi_x"
    result = redact_json({"a": 1, secret_key: 2}, max_nodes=2)
    assert result.value == {"a": 1, SIZE_LIMIT: SIZE_LIMIT}


def test_a_key_longer_than_the_key_cap_is_replaced():
    assert redact_json({"k" * 4097: "v"}).value == {SIZE_LIMIT: SIZE_LIMIT}


def test_keys_count_against_the_character_budget():
    value = {"abcdefghij": "v", "b": "w"}
    assert redact_json(value, max_chars=12).value == {"abcdefghij": "v", "b": SIZE_LIMIT}


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(object(), id="object"),
        pytest.param({1, 2}, id="set"),
        pytest.param(b"bytes", id="bytes"),
        pytest.param((1, 2), id="tuple"),
        pytest.param(math.nan, id="nan"),
        pytest.param(math.inf, id="infinity"),
    ],
)
@pytest.mark.parametrize("mode", ["strict", "compat"])
def test_a_value_outside_the_json_model_becomes_a_placeholder(bad, mode):
    result = redact_json({"a": [bad]}, mode=mode)
    assert result.value == {"a": [FAILED]}
    assert result.hits == (("redaction-failed", 1),)


def test_a_non_string_key_replaces_its_container():
    assert redact_json({"a": {1: "x"}}).value == {"a": FAILED}


def test_a_cycle_becomes_a_placeholder():
    looped = []
    looped.append(looped)
    assert redact_json({"a": looped}).value == {"a": ["[REDACTED:circular]"]}


def test_a_very_deep_value_is_walked_without_recursion():
    depth = 20_000
    value = current = []
    for _ in range(depth):
        nested = []
        current.append(nested)
        current = nested
    current.append("password=Zq9abcDEF123ghi_x")
    out = redact_json(value, max_depth=depth + 5, max_nodes=depth * 2, max_chars=10**6).value
    steps = 0
    while out and isinstance(out[0], list):
        out = out[0]
        steps += 1
    assert (steps, out) == (depth, ["password=[REDACTED:generic-keyword]"])


def test_the_default_depth_limit_holds_for_deep_input():
    value = current = []
    for _ in range(100):
        nested = []
        current.append(nested)
        current = nested
    out = redact_json(value).value
    steps = 0
    while isinstance(out, list) and out:
        out = out[0]
        steps += 1
    assert (steps, out) == (64, "[REDACTED:depth-limit]")


def test_an_invalid_mode_is_refused():
    with pytest.raises(ValueError):
        redact_text("x", mode="loose")  # type: ignore[arg-type]


def test_a_float_that_is_not_finite_still_becomes_a_placeholder():
    assert redact_json({"a": 1e999}).value == {"a": FAILED}


@pytest.mark.parametrize("digits", [10, 11, 5000, 100_000])
def test_an_overlong_numeric_key_does_not_fail_the_value_in_strict(digits):
    out = redact_json({"a": 1, "9" * digits: "v"}).value
    expected = {"a": 1, SIZE_LIMIT: SIZE_LIMIT} if digits > 4096 else {"a": 1, "9" * digits: "v"}
    assert out == expected


@pytest.mark.parametrize("digits", [10, 11, 5000, 100_000])
def test_an_overlong_numeric_key_does_not_fail_the_value_in_compat(digits):
    key = "9" * digits
    assert redact_json({"a": 1, key: "v"}, mode="compat").value == {"a": 1, key: "v"}


def test_numeric_keys_around_the_array_index_limit_are_ordered_as_ecmascript_orders_them():
    value = {"b": 0, "4294967295": 1, "4294967294": 2, "99999999999": 3, "10": 4, "9": 5}
    keys = list(redact_json(value, mode="compat").value)
    assert keys == ["9", "10", "4294967294", "b", "4294967295", "99999999999"]


@pytest.mark.parametrize("skip", ["id", b"id", 5])
def test_skip_keys_must_be_a_collection_of_strings(skip):
    with pytest.raises(TypeError):
        redact_json({"id": TOKEN}, skip_keys=skip)
