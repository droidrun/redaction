"""Replay of the recorded corpus (spec/corpus/golden-b12879a.json.gz, the TypeScript reference output).

Every case, both tiers in compat mode: the standard tier must equal the recorded `sync` result, the full tier
the recorded `async` result (the output, and the rule counts of the recorded hits; the full-tier rule ids of
the 0.2.0 record carry the prefix `@secretlint/secretlint-rule-`, the placeholder and this package do not).
A recorded output longer than 20,000 characters is stored as its SHA-256 and length; the replay compares
those.

Two groups differ on the full side, both by decision of Lutz (2026-11-18), and both are enumerated:
the AWS secret access key (SPEC 4.17) is reported over the secret, not from the key name, so the key name
stays (`AWS_SECRET_ACCESS_KEY=[REDACTED:aws]` where 0.2.0 recorded `[REDACTED:aws]`; the same exception is in
`ts/src/golden.test.ts`); and object keys are scanned with the full rules (L-N): 24 cases whose key is itself
a full-tier token (an npm, SendGrid, Slack, Linear, Shopify or GitLab token, or a database URL) now have that
key replaced by its placeholder.
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
# Object keys that are full-tier tokens (L-N, Lutz 2026-11-18): the recorded 0.2.0 output left them, or
# redacted only the password of a URL in them; the full tier now replaces the whole key.
DATABASE_URL = "[REDACTED:database-connection-string]"
FULL_KEY_RENAMES = {
    "postgres://app:[REDACTED:url-credentials]@db.example.test:5432/app": DATABASE_URL,
    "mongodb+srv://admin:[REDACTED:url-credentials]@cluster0.example.test/db": DATABASE_URL,
    "postgres://user:[REDACTED:url-credentials]@db.example.test:5432/app": DATABASE_URL,
    "npm_8sm7OXhsKGb9ECZOWLzYB1kfKvQRdckR5v8p": "[REDACTED:npm]",
    "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": "[REDACTED:sendgrid]",
    "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX": "[REDACTED:slack]",
    "lin_api_HZnTQA00zaX9FHQIppNWPLOlaAuBbPikE26OHX5q": "[REDACTED:linear]",
    "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": "[REDACTED:shopify]",
    "glpat-s7UFmkxn32UiKz2tBhmt": "[REDACTED:gitlab]",
}
FULL_KEY_CASES = [
    *(f"sample-{number}" for number in (68, 119, 122, 125, 128, 131, 137, 140)),
    *(
        f"fuzz-key-{number}"
        for number in (39, 57, 82, 127, 167, 189, 193, 198, 201, 211, 214, 236, 266, 274, 280, 284)
    ),
]


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


def rename_keys(value, mapping):
    """`value` with every object key in `mapping` renamed (a later key replaces an equal earlier one)."""
    if isinstance(value, dict):
        return {mapping.get(key, key): rename_keys(item, mapping) for key, item in value.items()}
    if isinstance(value, list):
        return [rename_keys(item, mapping) for item in value]
    return value


def test_every_case_gives_the_recorded_full_result_but_the_enumerated_ones():
    differing = replay("full", "async")
    by_id = {item["id"]: item for item in CORPUS["cases"]}
    assert [case_id for case_id, _ in differing] == sorted(
        [*AWS_CORRECTION, *FULL_KEY_CASES], key=[item["id"] for item in CORPUS["cases"]].index
    )
    for case_id, value in differing:
        if case_id in AWS_CORRECTION:
            expected = AWS_CORRECTION[case_id]
            assert by_id[case_id]["input"] == expected["input"]
            assert by_id[case_id]["async"]["out"] == expected["recorded"]
            assert value == expected["now"]
        else:
            # Only object keys differ: the full tier scans keys with the full rules (L-N), so a key that
            # is itself a full-tier token is replaced by its placeholder where 0.2.0 left it or only
            # redacted the URL password inside it.
            assert value == rename_keys(by_id[case_id]["async"]["out"], FULL_KEY_RENAMES)
