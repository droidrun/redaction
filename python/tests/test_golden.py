"""Replay of the recorded corpus (spec/corpus/golden-b12879a.json.gz, the TypeScript reference output).

Every case, both tiers in compat mode: the standard tier must equal the recorded `sync` result, the full tier
the recorded `async` result (the output, and the rule counts of the recorded hits; the full-tier rule ids of
the 0.2.0 record carry the prefix `@secretlint/secretlint-rule-`, the placeholder and this package do not).
A recorded output longer than 20,000 characters is stored as its SHA-256 and length; the replay compares
those.

ONE case differs on the full side, by decision of Lutz (2026-11-18, SPEC 4.17): the AWS secret access key is
reported over the secret, not from the key name, so the key name stays (`AWS_SECRET_ACCESS_KEY=[REDACTED:aws]`
where 0.2.0 recorded `[REDACTED:aws]`). The same exception is enumerated in `ts/src/golden.test.ts`.
"""

import hashlib
import json
import re
from collections import Counter

from helpers import canonical, expand_gen, load_corpus, run

CORPUS = load_corpus()
SURROGATE = re.compile("[\ud800-\udfff]")


def case_input(item):
    return expand_gen(item["gen"]) if "gen" in item else item["input"]


def utf16_length(text):
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def js_json_string(text):
    """`JSON.stringify(text)`: lone surrogates are written as escapes, everything else as UTF-8 text."""
    dumped = json.dumps(text, ensure_ascii=False)
    paired = dumped.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")
    return SURROGATE.sub(lambda unit: f"\\u{ord(unit.group()):04x}", paired)


def digest_of(text):
    serialized = js_json_string(text)
    return {
        "digest": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "length": utf16_length(serialized),
    }


def is_digest(recorded):
    return isinstance(recorded, dict) and set(recorded) == {"digest", "length"}


AWS_CORRECTION = {
    "vector-109": {
        "input": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzKEY9xxx1",
        "recorded": "[REDACTED:aws]",
        "now": "AWS_SECRET_ACCESS_KEY=[REDACTED:aws]",
    }
}
LEGACY_PREFIX = "@secretlint/secretlint-rule-"


def test_the_corpus_holds_at_least_5000_cases():
    assert len(CORPUS["cases"]) == CORPUS["count"]
    assert CORPUS["count"] >= 5000


def replay(tier, side):
    """The ids of the cases that differ from the recorded result of `side`, and how many were replayed."""
    differing = []
    for item in CORPUS["cases"]:
        result = run(case_input(item), mode="compat", opts=item.get("opts", {}), tier=tier)
        recorded = item[side]
        ids = (rule_id.removeprefix(LEGACY_PREFIX) for rule_id, _start, _end in recorded["hits"])
        counts = Counter(ids)
        output = digest_of(result.value) if is_digest(recorded["out"]) else result.value
        same_output = canonical(output) == canonical(recorded["out"])
        same_counts = dict(result.hits) == dict(counts)
        if result.error is not None or not same_output or not same_counts:
            differing.append((item["id"], result.value))
    return differing


def test_every_case_gives_the_recorded_standard_result():
    assert replay("standard", "sync") == []


def test_every_case_gives_the_recorded_full_result_but_the_aws_correction():
    differing = replay("full", "async")
    assert [case_id for case_id, _ in differing] == list(AWS_CORRECTION)
    by_id = {item["id"]: item for item in CORPUS["cases"]}
    for case_id, value in differing:
        expected = AWS_CORRECTION[case_id]
        assert by_id[case_id]["input"] == expected["input"]
        assert by_id[case_id]["async"]["out"] == expected["recorded"]
        assert value == expected["now"]
