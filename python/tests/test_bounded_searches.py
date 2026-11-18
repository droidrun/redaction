"""Searches that must stay bounded: a PEM header and a query value never scan the rest of the text.

Expected values were produced by the TypeScript package (its unbounded searches give the same output).
"""

import time

import pytest
from droidrun_redaction import redact_text

HEADER = "-----BEGIN PRIVATE KEY-----"
FOOTER = "-----END PRIVATE KEY-----"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(f"{HEADER}\nQUJD\n{FOOTER} tail", "[REDACTED:private-key] tail", id="complete block"),
        pytest.param(f"{HEADER}\nQUJD\n{FOOTER}", "[REDACTED:private-key]", id="footer at the very end"),
        pytest.param(f"{HEADER}\nQUJD", "[REDACTED:private-key]", id="unterminated block"),
        pytest.param(f"{HEADER}!{FOOTER}", f"[REDACTED:private-key]!{FOOTER}", id="body stops before footer"),
        pytest.param(f"{HEADER}-----END", "[REDACTED:private-key]", id="marker flush with the body end"),
        pytest.param(f"{HEADER}\n-----EN!{FOOTER}", f"[REDACTED:private-key]!{FOOTER}", id="cut marker"),
        pytest.param(
            f"{HEADER}\nQQ\n{HEADER}\nQQ\n{FOOTER}", "[REDACTED:private-key]", id="header inside a block"
        ),
        pytest.param(f"{HEADER}!{HEADER}!", "[REDACTED:private-key]![REDACTED:private-key]!", id="two"),
    ],
)
def test_pem_blocks(text, expected):
    assert redact_text(text, mode="compat").value == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "?password=Zq9abcDEF123ghi_x&b=1", "?password=[REDACTED:generic-keyword]&b=1", id="cut at &"
        ),
        pytest.param(
            "x=1?password=Zq9abcDEF123ghi_x&b=2&c", "x=1?password=[REDACTED:generic-keyword]&b=2&c", id="cut"
        ),
        pytest.param(
            "?password=Zq9abcDEF123ghi_x", "?password=[REDACTED:generic-keyword]", id="no & after the value"
        ),
        pytest.param("password=Zq9abc&DEF123ghi_x", "password=[REDACTED:generic-keyword]", id="no query"),
    ],
)
def test_query_value_cut(text, expected):
    assert redact_text(text, mode="compat").value == expected


def test_a_pem_header_does_not_scan_the_rest_of_the_text():
    text = (HEADER + "!") * 40_000
    started = time.perf_counter()
    result = redact_text(text, mode="compat")
    assert time.perf_counter() - started < 3
    assert result.value == "[REDACTED:private-key]!" * 40_000


def test_a_query_value_does_not_scan_the_rest_of_the_text():
    repeats = 160_000
    text = "?password=Ab1defgh " * repeats
    started = time.perf_counter()
    result = redact_text(text, mode="compat")
    assert time.perf_counter() - started < 5
    assert result.value == "?password=[REDACTED:generic-keyword] " * repeats
