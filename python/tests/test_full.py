"""The full tier (SPEC 4.11 to 4.17, 5.6, 5.7, 9.4): letter guard, base64 JSON, run memory, failures, API.

Expected values were produced by the TypeScript package and are written out here as literals.
"""

import base64
import json

import droidrun_redaction
import pytest
from droidrun_redaction import _detect, _scan_support, key_verdict, redact_json, redact_text
from droidrun_redaction._base64_json import decode_base64, is_base64_json
from droidrun_redaction._letters import is_letter, passes_letter_guard
from droidrun_redaction._placeholder import is_whole_placeholder
from helpers import fail_standard_rules

NPM = "npm_" + "A" * 36
GITHUB = "ghp_" + "a" * 36


@pytest.mark.parametrize(
    ("code_point", "expected"),
    [
        (0x40, False),
        (0x41, True),
        (0x5A, True),
        (0x5B, False),
        (0x61, True),
        (0x7B, False),
        (0xAA, True),
        (0xD7, False),
        (0x2C1, True),
        (0x2C2, False),
        (0x378, False),
        (0x1D400, True),
        (0x1E943, True),
        (0x1F600, False),
        (0x31350, True),
        (0x323AF, True),
        (0x323B0, False),
        (0x2B739, True),
        (0x2B73A, False),
        (0x1C89, False),
        (0xA7C0, True),
        (0xE0000, False),
        (0x10FFFF, False),
        (0xD800, False),
        (0xDFFF, False),
    ],
)
def test_letter_table_is_unicode_15(code_point, expected):
    assert is_letter(code_point) is expected


def test_letter_table_holds_136104_code_points():
    assert sum(is_letter(code_point) for code_point in range(0x110000)) == 136104


@pytest.mark.parametrize(
    ("units", "expected"),
    [
        ("a", False),
        ("1", True),
        ("é", False),
        ("𝐀", False),
        ("\U0001f600".encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass"), True),
        ("\ud800", True),
        ("\udc00", True),
        ("\ud835", True),
    ],
)
def test_letter_guard_reads_the_code_point_before(units, expected):
    # `units` is a unit string: an astral letter is its two surrogates; a lone surrogate is no letter.
    assert passes_letter_guard(units + "x", len(units)) is expected


def test_letter_guard_passes_at_the_start():
    assert passes_letter_guard("npm_", 0) is True


@pytest.mark.parametrize(
    ("prefix", "redacted"),
    [
        ("x", False),
        ("é", False),
        ("1", True),
        ("_", True),
        (" ", True),
        ("\ud800", True),
        ("𝐀", False),
        ("\U0001f600", True),
    ],
)
def test_a_token_behind_a_letter_is_not_a_token(prefix, redacted):
    result = redact_text(prefix + NPM, tier="full", mode="compat")
    assert (result.value == prefix + "[REDACTED:npm]") is redacted
    assert (result.value == prefix + NPM) is not redacted


def b64(text: str) -> str:
    return base64.b64encode(text.encode("latin-1")).decode("ascii")


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        (b64('{"a":1}'), True),
        (b64("[]"), True),
        (b64("{}"), True),
        (b64(' \t\r\n{"a": [1, -2.5e+3, true, false, null, "x\\u00e9\\n"]}\n'), True),
        (b64('{"a":{"b":[{"c":[]}]}}'), True),
        (b64('"text"'), False),
        (b64("42"), False),
        (b64("true"), False),
        (b64('{"a":1,}'), False),
        (b64("[1,]"), False),
        (b64('{"a":1}x'), False),
        (b64('{"a":NaN}'), False),
        (b64("{'a':1}"), False),
        (b64('{"a":01}'), False),
        (b64('{"a":1.}'), False),
        (b64('{"a":"\\x"}'), False),
        (b64('{"a":"\\u12G4"}'), False),
        (b64('{"a":"\x01"}'), False),
        (b64('{"a"}'), False),
        (b64('{"a":1'), False),
        (b64(""), False),
        (b64('{"a":1}')[:-1] + "=", True),
        ("e30=", True),
        ("e30", True),
        ("e3", False),
        ("e", False),
        ("e30==", False),
        ("e=30", False),
        ("e30*", False),
    ],
)
def test_base64_json_check(token, expected):
    assert is_base64_json(token) is expected


def test_base64_decode_drops_bits_that_do_not_fill_a_byte():
    assert decode_base64("e30") == b"{}"
    assert decode_base64("e30=") == b"{}"
    assert decode_base64("e3") == b"{"
    assert decode_base64("e") is None


def test_base64_json_check_is_iterative():
    depth = 200_000
    token = b64("[" * depth + "]" * depth)
    assert is_base64_json(token) is True
    assert is_base64_json(b64("[" * depth + "]" * (depth - 1))) is False


def one_password(body: dict, tail: str = "") -> str:
    """A token the rule reads: the JSON padded inside so that its base64 ends with `fQ==`."""
    raw = json.dumps(body, separators=(",", ":"))
    padding = " " * ((1 - len(raw)) % 3)
    return "ops_" + b64("{" + padding + raw[1:] + tail)


ONE_PASSWORD_BODY = {
    "signInAddress": "my.1password.com",
    "userAuth": {"method": "SRPg-4096", "alg": "PBES2g-HS256", "iterations": 650000},
    "email": "a@b.c",
}


def test_a_one_password_token_needs_a_json_body():
    real = one_password(ONE_PASSWORD_BODY)
    assert real.endswith("fQ==")
    assert redact_text(f"x {real} y", tier="full", mode="compat").value == "x [REDACTED:1password] y"
    broken = one_password(ONE_PASSWORD_BODY, tail="x")
    assert redact_text(f"x {broken} y", tier="full", mode="compat").value == f"x {broken} y"
    not_json = "ops_ey" + "A" * 130
    assert redact_text(f"x {not_json} y", tier="full", mode="compat").value == f"x {not_json} y"


def counting(monkeypatch):
    """Counts the units the run measurements walk (what a run memory exists to keep small)."""
    walked = []
    real = _scan_support.run_end

    def measure(run, text, start, limit=None):
        end = real(run, text, start, limit)
        walked.append(end - start)
        return end

    monkeypatch.setattr(_scan_support, "run_end", measure)
    return walked


def test_a_run_memory_per_part_keeps_a_repeated_cluster_linear(monkeypatch):
    # `ghs_1_` x 170, `.`, then a long run of one class that three parts of the `ghs_` shape share.
    text = "ghs_1_" * 170 + "." + "a" * 200_000
    walked = counting(monkeypatch)
    result = redact_text(text, tier="full", mode="compat")
    assert result.value == text
    assert sum(walked) < 4 * len(text)


def test_a_run_memory_per_part_keeps_dash_chains_and_sendgrid_linear(monkeypatch):
    for unit in ("xoxb-a-", "SG.a.a-", "SG.a.aSG.a."):
        text = unit * 20_000
        walked = counting(monkeypatch)
        redact_text(text, tier="full", mode="compat")
        assert sum(walked) < 6 * len(text)
        walked.clear()


class ScanBroken(Exception):
    pass


SECRET = "Zq9abcDEF123ghi_x"


def failing(units):
    """Breaks only on a text that holds the secret: `strict` scans every text, short keys and values too."""
    if SECRET in units:
        raise ScanBroken(f"cannot scan {units}")
    return []


TEXT = f"{NPM} password={SECRET}"
FALLBACK = f"{NPM} password=[REDACTED:generic-keyword]"
JSON_VALUE = {"a": "short", "b": TEXT}


def break_full_rules(monkeypatch):
    monkeypatch.setattr(_detect, "_FULL_PIPELINE", [("npm", failing)])


def break_all_rules(monkeypatch):
    break_full_rules(monkeypatch)
    fail_standard_rules(monkeypatch, failing)


def test_error_is_none_when_nothing_failed():
    for call in (
        redact_text(TEXT, tier="full"),
        redact_text(TEXT, tier="full", mode="compat"),
        redact_json(JSON_VALUE, tier="full"),
        redact_json(JSON_VALUE, tier="full", mode="compat"),
    ):
        assert call.error is None


def test_compat_text_falls_back_to_the_standard_rules_and_reports_the_failure(monkeypatch):
    break_full_rules(monkeypatch)
    result = redact_text(TEXT, tier="full", mode="compat")
    assert (result.value, result.error) == (FALLBACK, "ScanBroken")
    assert result.hits == (("generic-keyword", 1),)
    assert SECRET not in repr(result)


def test_compat_text_is_replaced_when_the_standard_rules_fail_too(monkeypatch):
    break_all_rules(monkeypatch)
    result = redact_text(TEXT, tier="full", mode="compat")
    assert (result.value, result.hits, result.error) == ("[REDACTED:error]", (("error", 1),), "ScanBroken")
    assert SECRET not in repr(result)


def test_strict_text_is_replaced_without_a_fallback(monkeypatch):
    break_full_rules(monkeypatch)
    result = redact_text(TEXT, tier="full")
    assert (result.value, result.hits, result.error) == ("[REDACTED:error]", (("error", 1),), "ScanBroken")


def test_strict_json_reports_the_failure_of_a_leaf(monkeypatch):
    break_full_rules(monkeypatch)
    result = redact_json(JSON_VALUE, tier="full")
    assert result.value == {"a": "short", "b": "[REDACTED:error]"}
    assert (result.hits, result.error) == ((("error", 1),), "ScanBroken")
    assert SECRET not in repr(result)


def test_compat_json_falls_back_per_leaf_and_reports_the_failure(monkeypatch):
    break_full_rules(monkeypatch)
    result = redact_json(JSON_VALUE, tier="full", mode="compat")
    assert result.value == {"a": "short", "b": FALLBACK}
    assert result.error == "ScanBroken"


def test_compat_json_replaces_a_leaf_when_the_standard_rules_fail_too(monkeypatch):
    break_all_rules(monkeypatch)
    result = redact_json(JSON_VALUE, tier="full", mode="compat")
    assert result.value == {"a": "short", "b": "[REDACTED:error]"}
    assert result.error == "ScanBroken"


def test_json_keeps_the_first_failure(monkeypatch):
    class Later(Exception):
        pass

    calls = []

    def breaking(units):
        if SECRET not in units:
            return []
        calls.append(units)
        raise (ScanBroken if len(calls) == 1 else Later)(units)

    monkeypatch.setattr(_detect, "_FULL_PIPELINE", [("npm", breaking)])
    result = redact_json({"a": TEXT, "b": TEXT}, tier="full")
    assert (result.value, result.error) == ({"a": "[REDACTED:error]", "b": "[REDACTED:error]"}, "ScanBroken")


def test_a_failing_standard_leaf_is_reported_too(monkeypatch):
    fail_standard_rules(monkeypatch, failing)
    result = redact_json(JSON_VALUE)
    assert result.value == {"a": "short", "b": "[REDACTED:redaction-failed]"}
    assert result.error == "ScanBroken"


@pytest.mark.parametrize(
    ("text", "limit", "kept"),
    [
        ("\U0001f511" * 6, 10, False),
        ("\U0001f511" * 5, 10, True),
        ("\U0001f511" * 6, 12, True),
        ("\U0001f511" * 6, 11, False),
        ("\U0001f511" * 3 + "a" * 5, 11, True),
        ("\U0001f511" * 3 + "a" * 5, 10, False),
        ("a" * 10, 10, True),
        ("a" * 11, 10, False),
    ],
)
@pytest.mark.parametrize("tier", ["standard", "full"])
def test_the_character_cap_counts_utf16_units(text, limit, kept, tier):
    result = redact_text(text, tier=tier, max_chars=limit)
    assert (result.value == text) is kept
    assert kept or result.value == "[REDACTED:size-limit]"


def test_the_default_tier_is_standard():
    assert redact_text(NPM).value == NPM
    assert redact_text(NPM, tier="full").value == "[REDACTED:npm]"
    assert redact_json({"a": NPM}).value == {"a": NPM}
    assert redact_json({"a": NPM}, tier="full").value == {"a": "[REDACTED:npm]"}


def test_an_unknown_tier_is_refused():
    with pytest.raises(ValueError):
        redact_text("x", tier="max")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        redact_json({}, tier="max")  # type: ignore[arg-type]


def test_hits_name_the_rules_by_their_spec_id():
    text = f"{NPM} {GITHUB} AKIAQR7ZKT4MW2PLX9BD"
    result = redact_text(text, tier="full")
    assert result.value == "[REDACTED:npm] [REDACTED:github] [REDACTED:aws]"
    assert result.hits == (("npm", 1), ("github", 1), ("aws", 1))


def test_full_tier_strict_cap_applies_and_compat_has_none():
    text = NPM + " " * 20
    assert redact_text(text, tier="full", max_chars=10).value == "[REDACTED:size-limit]"
    assert redact_text(text, tier="full", mode="compat").value == "[REDACTED:npm]" + " " * 20


@pytest.mark.parametrize("limit", ["max_chars", "max_depth", "max_nodes"])
def test_full_tier_compat_refuses_a_limit(limit):
    with pytest.raises(ValueError, match=limit):
        redact_json({"a": NPM}, tier="full", mode="compat", **{limit: 5})
    with pytest.raises(ValueError, match=limit):
        redact_json({"a": NPM}, tier="full", mode="compat", **{limit: 0})


def test_full_tier_compat_text_refuses_max_chars():
    with pytest.raises(ValueError, match="max_chars"):
        redact_text(NPM, tier="full", mode="compat", max_chars=10)
    with pytest.raises(ValueError, match="max_chars"):
        redact_text(NPM, tier="full", mode="compat", max_chars=0)


def test_limits_stay_valid_in_strict_and_in_the_standard_tier():
    value = {"a": {"b": {"c": [NPM, NPM]}}}
    assert redact_json(value, tier="full", max_depth=1).value == {"a": "[REDACTED:depth-limit]"}
    assert redact_json(value, mode="compat", max_depth=1).value == {"a": "[REDACTED:depth-limit]"}
    assert redact_text(NPM, max_chars=10).value == "[REDACTED:size-limit]"
    assert redact_text(NPM, mode="compat", max_chars=10).value == "[REDACTED:size-limit]"
    assert redact_json(value, tier="full", mode="compat").value == {
        "a": {"b": {"c": ["[REDACTED:npm]", "[REDACTED:npm]"]}}
    }


@pytest.mark.parametrize("mode", ["strict", "compat"])
def test_full_tier_keys_are_scanned_with_the_full_rules(mode):
    secret_key = f"password={SECRET}"
    value = {NPM: 2, f"label {NPM}": 3, secret_key: 1, "plain": NPM}
    out = redact_json(value, tier="full", mode=mode)
    assert out.value == {
        "[REDACTED:npm]": 2,
        "label [REDACTED:npm]": 3,
        "password=[REDACTED:generic-keyword]": "[REDACTED:key-context]",
        "plain": "[REDACTED:npm]",
    }
    assert out.hits == (("npm", 3), ("generic-keyword", 1), ("key-context", 1))
    assert out.error is None


@pytest.mark.parametrize("mode", ["strict", "compat"])
def test_the_standard_tier_leaves_a_full_only_token_in_a_key(mode):
    assert redact_json({NPM: 2}, mode=mode).value == {NPM: 2}


def test_a_key_that_is_a_one_password_or_slack_token_is_replaced():
    slack = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
    key = one_password(ONE_PASSWORD_BODY)
    out = redact_json({slack: 1, key: 2}, tier="full").value
    assert out == {"[REDACTED:slack]": 1, "[REDACTED:1password]": 2}


DB_URL = "postgres://user:Zq9abcDEF123ghi_x@db.example.test:5432/app"
OTHER_DB_URL = "postgres://other:Qw8rtyUIO456jkl_z@db2.example.test:5432/app"


@pytest.mark.parametrize("mode", ["strict", "compat"])
def test_two_database_url_keys_count_both_hits(mode):
    out = redact_json({DB_URL: "first", OTHER_DB_URL: "second"}, tier="full", mode=mode)
    assert out.hits == (("database-connection-string", 2),)


OTHER_NPM = "npm_" + "B" * 36


def test_strict_a_reserved_key_that_the_budget_replaces_keeps_its_name_reserved():
    # The first key takes the whole budget (40); the literal placeholder key after it is replaced by the
    # size-limit placeholder, and the scan for reserved names stopped before it, so it is not reserved.
    value = {NPM: 2, "[REDACTED:size-limit]": 1, "other": 3, "more": 4}
    out = redact_json(value, tier="full", max_chars=40).value
    assert list(out.items()) == [
        ("[REDACTED:npm]", 2),
        ("[REDACTED:size-limit]", 1),
        ("[REDACTED:size-limit#2]", 3),
        ("[REDACTED:size-limit#3]", 4),
    ]


def test_strict_a_size_limit_key_equal_to_an_input_key_is_still_a_changed_key():
    value = {"[REDACTED:npm]" + "x" * 5000: 1, NPM: 2, "[REDACTED:size-limit]": 3}
    assert list(redact_json(value, tier="full").value.items()) == [
        ("[REDACTED:size-limit#2]", 1),
        ("[REDACTED:size-limit#3]", 2),
        ("[REDACTED:size-limit#4]", 3),
    ]


def test_compat_a_key_over_the_limit_that_holds_a_placeholder_is_left_and_reserved():
    long_key = "[REDACTED:npm]" + "x" * 5000
    out = redact_json({long_key: 1, NPM: 2}, tier="full", mode="compat").value
    assert list(out.items()) == [(long_key, 1), ("[REDACTED:npm]", 2)]


def test_a_numbered_key_is_a_placeholder_and_the_output_is_a_fixed_point():
    value = {DB_URL: "first", OTHER_DB_URL: "second", NPM: "third", f"password={SECRET}": "x"}
    once = redact_json(value, tier="full")
    twice = redact_json(once.value, tier="full")
    assert twice.value == once.value
    assert twice.hits == ()
    assert is_whole_placeholder("[REDACTED:npm#2]")
    assert redact_text("[REDACTED:npm#2]", tier="full").value == "[REDACTED:npm#2]"
    assert redact_json({"k": "[REDACTED:npm#2]"}, tier="full").value == {"k": "[REDACTED:npm#2]"}
    assert redact_json({"password": "[REDACTED:npm#2]"}).value == {"password": "[REDACTED:npm#2]"}


def test_a_numbered_key_is_read_without_its_placeholder_for_the_key_verdict():
    assert key_verdict("[REDACTED:generic-keyword#2]") == "none"
    assert key_verdict("password=[REDACTED:generic-keyword#2]") == "any"


def test_a_failing_key_scan_is_reported(monkeypatch):
    break_full_rules(monkeypatch)
    strict = redact_json({TEXT: 1}, tier="full")
    assert strict.value == {"[REDACTED:error]": "[REDACTED:key-context]"}
    assert strict.error == "ScanBroken"
    compat = redact_json({TEXT: 1}, tier="full", mode="compat")
    assert compat.value == {FALLBACK: "[REDACTED:key-context]"}
    assert compat.error == "ScanBroken"


def test_an_over_long_full_tier_key_is_left_as_it_is_in_compat_and_replaced_in_strict():
    key = NPM + "x" * 5000
    assert redact_json({key: 1}, tier="full", mode="compat").value == {key: 1}
    assert redact_json({key: 1}, tier="full").value == {"[REDACTED:size-limit]": 1}


def test_module_exports_the_tier_type():
    assert droidrun_redaction.Tier is not None


@pytest.mark.parametrize(
    ("start", "found"),
    [(89759, False), (89760, True), (89761, False), (179519, False), (179520, True), (179521, False)],
)
def test_a_window_start_has_no_letter_in_front_of_it(start, found):
    # The windows start at multiples of 89,760 units (100,000 minus the overlap of 10,240). A window is
    # scanned as its own text, so a token that starts exactly there passes the letter guard even behind a
    # letter: the TypeScript package finds it, and so does this one.
    text = " " * (start - 1) + "x" + NPM + " " * (190_000 - start - 40)
    assert ("[REDACTED:npm]" in redact_text(text, tier="full", mode="compat").value) is found
