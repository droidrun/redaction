"""Metadata (SPEC section 11): hits are rule id and count only; no input fragment reaches an error."""

import pytest
from droidrun_redaction import (
    RedactResult,
    RuleCount,
    _detect,
    _keys,
    _scan,
    _walk,
    is_secret_key_name,
    key_verdict,
    redact_json,
    redact_text,
)
from droidrun_redaction._spec import SpecError

SECRET = "Zq9abcDEF123ghi_x"


def test_text_hits_are_rule_ids_and_counts():
    result = redact_text(f"password={SECRET} and token=Qw8rtyUIO456jkl_z")
    assert result.hits == (RuleCount("generic-keyword", 2),)
    assert isinstance(result, RedactResult)


def test_json_hits_are_counted_per_rule_in_order_of_first_hit():
    value = {"password": "hunter2", "note": f"Bearer {SECRET}", "other": f"password={SECRET}"}
    result = redact_json(value)
    assert result.hits == (
        RuleCount("key-context", 1),
        RuleCount("auth-header", 1),
        RuleCount("generic-keyword", 1),
    )


def test_a_result_holds_no_range_and_no_matched_text():
    text = f"password={SECRET}"
    result = redact_text(text)
    assert SECRET not in repr(result)
    assert [type(field) for field in result.hits[0]] == [str, int]


def test_a_failure_carries_the_error_class_and_no_input(monkeypatch):
    def failing(units):
        raise RuntimeError(f"cannot scan {units}")

    monkeypatch.setattr(_detect, "_PIPELINE", [("jwt", failing)])
    result = redact_text(f"password={SECRET}")
    assert result == RedactResult(
        "[REDACTED:redaction-failed]", (RuleCount("redaction-failed", 1),), "RuntimeError"
    )
    assert SECRET not in repr(result)


def test_a_failing_leaf_becomes_a_placeholder_in_strict_and_fails_the_value_in_compat(monkeypatch):
    def failing(units):
        raise RuntimeError(units)

    monkeypatch.setattr(_detect, "_PIPELINE", [("jwt", failing)])
    value = {"a": "short", "b": f"password={SECRET}"}
    strict = redact_json(value, mode="strict")
    assert strict.value == {"a": "short", "b": "[REDACTED:redaction-failed]"}
    assert strict.error == "RuntimeError"
    compat = redact_json(value, mode="compat")
    assert (compat.value, compat.error) == ("[REDACTED:redaction-failed]", "RuntimeError")
    assert SECRET not in repr(compat)


def test_an_unknown_rule_kind_in_the_spec_is_a_spec_error():
    with pytest.raises(SpecError):
        _detect._prepare({"id": "x", "kind": "no-such-kind"}, _detect._PREPARE)
    with pytest.raises(SpecError):
        _detect._prepare({"id": "x", "kind": "no-such-kind"}, _detect._FULL_PREPARE)


def test_a_text_over_the_cap_is_not_converted(monkeypatch):
    def refuse(text):
        raise AssertionError("converted")

    monkeypatch.setattr(_scan, "to_units", refuse)
    result = redact_text("a" * 11, max_chars=10)
    assert (result.value, result.hits, result.error) == ("[REDACTED:size-limit]", (("size-limit", 1),), None)


def test_a_leaf_and_a_key_over_the_budget_are_not_converted(monkeypatch):
    real = _walk.to_units

    def refuse_long(text):
        if len(text) > 4:
            raise AssertionError("converted")
        return real(text)

    monkeypatch.setattr(_walk, "to_units", refuse_long)
    assert redact_json({"a": "b" * 11}, max_chars=10).value == {"a": "[REDACTED:size-limit]"}
    assert redact_json({"k" * 11: "b"}, max_chars=10).value == {
        "[REDACTED:size-limit]": "[REDACTED:size-limit]"
    }
    assert redact_json({"k" * 5000: "b"}).value == {"[REDACTED:size-limit]": "[REDACTED:size-limit]"}


def test_a_long_key_is_not_kept_in_the_key_cache():
    before = _keys._evaluate_cached.cache_info().currsize
    assert not is_secret_key_name("ab_" * 200)
    assert key_verdict("password" + "x" * 300) == "none"
    assert _keys._evaluate_cached.cache_info().currsize == before
    assert is_secret_key_name("api_key_for_cache_test")
    assert _keys._evaluate_cached.cache_info().currsize == before + 1
