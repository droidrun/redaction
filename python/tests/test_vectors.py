"""Every case of spec/vectors/*.json: the standard tier against `expectedSync`, the full tier against
`expectedAsync` (or `expected`), in the mode the case names."""

import pytest
from helpers import canonical, expand_gen, load_vector_files, run

CASES = [
    pytest.param(case, id=f"{name}:{case['name']}")
    for name, file in load_vector_files()
    for case in file["cases"]
]
TIERS = ["standard", "full"]


def expected_for(case, tier):
    if "expected" in case:
        return case["expected"]
    if tier == "standard":
        return expand_gen(case["expectedGenSync"]) if "expectedGenSync" in case else case["expectedSync"]
    return expand_gen(case["expectedGenAsync"]) if "expectedGenAsync" in case else case["expectedAsync"]


def case_input(case):
    return expand_gen(case["inputGen"]) if "inputGen" in case else case["input"]


def test_every_category_is_present():
    names = [name for name, _ in load_vector_files()]
    assert names == [
        "auth-headers.json",
        "base64.json",
        "entropy.json",
        "false-positives.json",
        "full-keys.json",
        "full.json",
        "key-collisions.json",
        "key-formats.json",
        "key-names.json",
        "keywords.json",
        "modes.json",
        "nested-json.json",
        "pii.json",
        "url-query.json",
    ]


@pytest.mark.parametrize("tier", TIERS)
@pytest.mark.parametrize("case", CASES)
def test_case(case, tier):
    mode = case.get("mode", "compat")
    result = run(case_input(case), mode=mode, opts=case.get("opts", {}), tier=tier)
    assert result.error is None
    assert canonical(result.value) == canonical(expected_for(case, tier))


@pytest.mark.parametrize("tier", TIERS)
@pytest.mark.parametrize("case", CASES)
def test_expected_output_is_idempotent(case, tier):
    mode = case.get("mode", "compat")
    expected = expected_for(case, tier)
    result = run(expected, mode=mode, opts={}, tier=tier)
    assert canonical(result.value) == canonical(expected)
