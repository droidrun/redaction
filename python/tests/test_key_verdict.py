"""The public key verdict (SPEC section 6) and the logging-filter use of it."""

import pytest
from droidrun_redaction import is_secret_key_name, key_verdict, redact_json


@pytest.mark.parametrize(
    ("key", "verdict"),
    [
        ("password", "any"),
        ("pin", "any"),
        ("x-auth-token", "any"),
        ("apiKey", "any"),
        ("tokens", "string"),
        ("max_tokens", "string"),
        ("prompt_tokens", "string"),
        ("secretary", "none"),
        ("name", "none"),
        ("", "none"),
        ("password=[REDACTED:generic-keyword]", "any"),
        ("[REDACTED:generic-keyword]", "none"),
    ],
)
def test_key_verdict(key, verdict):
    assert key_verdict(key) == verdict


def test_the_verdict_agrees_with_is_secret_key_name():
    for key in ["password", "tokens", "max_tokens", "name", "Set-Cookie", "ABc", "APIKey"]:
        assert (key_verdict(key) != "none") is is_secret_key_name(key)


def test_a_logging_filter_replaces_strings_and_keeps_counts():
    record = {"user": "u1", "api_key": "k-123", "max_tokens": 100, "prompt_tokens": 12, "pin": 4321}
    out = redact_json(record).value
    assert out == {
        "user": "u1",
        "api_key": "[REDACTED:key-context]",
        "max_tokens": 100,
        "prompt_tokens": 12,
        "pin": "[REDACTED:key-context]",
    }
