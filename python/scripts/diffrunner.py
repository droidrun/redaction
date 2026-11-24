"""Python runner of the cross-language differential test (tools/diff).

Reads one request per line on stdin and writes one response per line on stdout:

    request:  {"id", "kind": "text"|"json", "tier", "mode", "opts", "input"}
    response: {"id", "out", "hits": [[ruleId, count], ...], "error"}

Run: uv run python scripts/diffrunner.py
"""

import json
import sys

import droidrun_redaction as redaction


def redact(request: dict):
    opts = request.get("opts") or {}
    common = {
        "mode": request["mode"],
        "pii": opts.get("pii", False),
        "max_chars": opts.get("maxChars"),
        "tier": request["tier"],
    }
    if request["kind"] == "text":
        return redaction.redact_text(request["input"], **common)
    return redaction.redact_json(
        request["input"],
        skip_keys=opts.get("skipKeys"),
        max_depth=opts.get("maxDepth"),
        max_nodes=opts.get("maxNodes"),
        **common,
    )


def compact(value) -> str:
    """Compact JSON, ASCII only: lone surrogates and astral characters are `\\u` escapes."""
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def respond(request: dict) -> str:
    try:
        result = redact(request)
    except Exception as error:  # an exception of the call is a `crash`: the driver fails the job on it
        crash = type(error).__name__
        return compact({"id": request["id"], "out": None, "hits": [], "error": None, "crash": crash})
    hits = [[hit.rule_id, hit.count] for hit in result.hits]
    # `out` is written by hand so that the redacted value keeps the order of its keys.
    return (
        f'{{"id":{compact(request["id"])},"out":{compact(result.value)},'
        f'"hits":{compact(hits)},"error":{compact(result.error)},"crash":null}}'
    )


def main() -> None:
    for line in sys.stdin:
        if line.strip():
            sys.stdout.write(respond(json.loads(line)) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
