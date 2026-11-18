"""Metadata (SPEC section 11): hits are rule id and count only; no input fragment reaches an error."""

from droidrun_redaction import RedactResult, RuleCount, redact_json, redact_text
from droidrun_redaction import _detect

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
    assert strict.error is None
    compat = redact_json(value, mode="compat")
    assert (compat.value, compat.error) == ("[REDACTED:redaction-failed]", "RuntimeError")
    assert SECRET not in repr(compat)
