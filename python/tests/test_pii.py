"""The `pii` option (SPEC 9.5) at the API: its type, the entry points it reaches and the scan floor (SPEC 9.1).

The behaviour of each rule is pinned by the vectors; this file covers what a vector cannot say about the call.
"""

import pytest
from droidrun_redaction import redact_json, redact_text

EMAIL = "[REDACTED:email]"


@pytest.mark.parametrize("pii", [1, "yes", None])
def test_pii_must_be_a_bool(pii):
    with pytest.raises(TypeError):
        redact_text("a@b.xx", pii=pii)
    with pytest.raises(TypeError):
        redact_json({"a": "a@b.xx"}, pii=pii)


@pytest.mark.parametrize("mode", ["strict", "compat"])
@pytest.mark.parametrize("tier", ["standard", "full"])
def test_pii_is_off_by_default_and_the_same_option_works_in_each_mode_and_tier(mode, tier):
    text = "mail me at jane@example.com"
    assert redact_text(text, mode=mode, tier=tier).value == text
    result = redact_text(text, mode=mode, tier=tier, pii=True)
    assert (result.value, result.hits) == (f"mail me at {EMAIL}", (("email", 1),))


@pytest.mark.parametrize("mode", ["strict", "compat"])
def test_pii_scans_a_text_shorter_than_the_compat_floor(mode):
    assert redact_text("a@b.xx", mode=mode, pii=True).value == EMAIL
    assert redact_text("a@b.xx", mode=mode).value == "a@b.xx"


def test_compat_without_pii_does_not_scan_a_short_text_and_strict_does():
    assert redact_text("token=x1y2z3", mode="compat").value == "token=x1y2z3"
    assert redact_text("token=x1y2z3", mode="strict").value == "token=[REDACTED:generic-keyword]"


@pytest.mark.parametrize("tier", ["standard", "full"])
def test_pii_reaches_the_values_and_the_keys_of_a_json_value(tier):
    value = {"jane@example.com": "mail jane@example.com"}
    result = redact_json(value, tier=tier, pii=True)
    assert result.value == {EMAIL: f"mail {EMAIL}"}
    assert redact_json(value, tier=tier).value == value
