"""Shared helpers of the conformance tests: loading vectors and the corpus, comparing outputs."""

import gzip
import json
from importlib import resources
from pathlib import Path
from typing import Any

import droidrun_redaction as redaction

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = REPO_ROOT / "spec" / "corpus" / "golden-b12879a.json.gz"


def expand_gen(gen: dict[str, Any]) -> str:
    return "".join(unit * times for unit, times in gen["parts"])


def load_vector_files() -> list[tuple[str, dict[str, Any]]]:
    root = resources.files("droidrun_redaction").joinpath("spec", "vectors")
    names = sorted(entry.name for entry in root.iterdir() if entry.name.endswith(".json"))
    return [(name, json.loads(root.joinpath(name).read_text(encoding="utf-8"))) for name in names]


def load_corpus() -> dict[str, Any]:
    with gzip.open(CORPUS_PATH, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def canonical(value: Any) -> Any:
    """Plain data in which key order counts and numbers are compared as doubles (SPEC sections 8 and 14)."""
    if isinstance(value, dict):
        return [["object", [[key, canonical(item)] for key, item in value.items()]]]
    if isinstance(value, list):
        return ["array", [canonical(item) for item in value]]
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    return ["number", float(value)]


def run(value: Any, *, mode: str, opts: dict[str, Any], tier: str = "standard") -> Any:
    """A string goes through the text entry point, any other JSON value through the JSON one."""
    if isinstance(value, str):
        return redaction.redact_text(value, tier=tier, mode=mode, max_chars=opts.get("maxChars"))
    return redaction.redact_json(
        value,
        tier=tier,
        mode=mode,
        max_chars=opts.get("maxChars"),
        max_depth=opts.get("maxDepth"),
        max_nodes=opts.get("maxNodes"),
        skip_keys=opts.get("skipKeys"),
    )
