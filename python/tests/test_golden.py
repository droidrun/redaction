"""Replay of the recorded corpus (spec/corpus/golden-b12879a.json.gz, the TypeScript reference output).

Every case whose input is a JSON value, standard tier, compat mode: the output must equal the recorded
`sync` output and the rule counts must equal the counts of the recorded hits. A recorded output longer
than 20,000 characters is stored as its SHA-256 and length; the replay compares those.
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


def test_the_corpus_holds_at_least_5000_cases():
    assert len(CORPUS["cases"]) == CORPUS["count"]
    assert CORPUS["count"] >= 5000


def test_every_case_gives_the_recorded_output_and_rule_counts():
    differing = []
    for item in CORPUS["cases"]:
        result = run(case_input(item), mode="compat", opts=item.get("opts", {}))
        recorded = item["sync"]
        counts = Counter(rule_id for rule_id, _start, _end in recorded["hits"])
        output = digest_of(result.value) if is_digest(recorded["out"]) else result.value
        same_output = canonical(output) == canonical(recorded["out"])
        same_counts = dict(result.hits) == dict(counts)
        if result.error is not None or not same_output or not same_counts:
            differing.append(item["id"])
    assert differing == []
