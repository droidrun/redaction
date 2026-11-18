"""Every case of spec/vectors/*.json, standard-tier side, in the mode the case names."""

import pytest
from helpers import canonical, expand_gen, load_vector_files, run

CASES = [
    pytest.param(case, id=f"{name}:{case['name']}")
    for name, file in load_vector_files()
    for case in file["cases"]
]


def standard_expected(case):
    if "expected" in case:
        return case["expected"]
    if "expectedGenSync" in case:
        return expand_gen(case["expectedGenSync"])
    return case["expectedSync"]


def case_input(case):
    return expand_gen(case["inputGen"]) if "inputGen" in case else case["input"]


def test_every_category_is_present():
    names = [name for name, _ in load_vector_files()]
    assert names == [
        "auth-headers.json",
        "base64.json",
        "entropy.json",
        "false-positives.json",
        "key-formats.json",
        "key-names.json",
        "keywords.json",
        "modes.json",
        "nested-json.json",
        "url-query.json",
    ]


@pytest.mark.parametrize("case", CASES)
def test_case(case):
    mode = case.get("mode", "compat")
    result = run(case_input(case), mode=mode, opts=case.get("opts", {}))
    assert result.error is None
    assert canonical(result.value) == canonical(standard_expected(case))


@pytest.mark.parametrize("case", CASES)
def test_expected_output_is_idempotent(case):
    mode = case.get("mode", "compat")
    expected = standard_expected(case)
    result = run(expected, mode=mode, opts={})
    assert canonical(result.value) == canonical(expected)
