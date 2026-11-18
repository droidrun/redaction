"""Python runner of the cross-language differential test (tools/diff).

Reads one request per line on stdin and writes one response per line on stdout:

    request:  {"id", "kind": "text"|"json", "tier", "mode", "opts", "input"}
    response: {"id", "out", "hits": [[ruleId, count], ...], "error"}

The first output line is {"capabilities": {...}}. Run: uv run python scripts/diffrunner.py
"""

import inspect
import json
import sys

import droidrun_redaction as redaction


def has_tier() -> bool:
    """True when this version of the package has the full tier (a `tier` argument)."""
    return "tier" in inspect.signature(redaction.redact_text).parameters


def capabilities() -> dict[str, list[str]]:
    modes = ["compat", "strict"]
    return {"standard": modes, "full": modes if has_tier() else []}


def redact(request: dict):
    opts = request.get("opts") or {}
    common = {"mode": request["mode"], "max_chars": opts.get("maxChars")}
    if has_tier():
        common["tier"] = request["tier"]
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
    except Exception as error:  # a runner reports a failure of the call, it does not stop
        return compact({"id": request["id"], "out": None, "hits": [], "error": type(error).__name__})
    hits = [[hit.rule_id, hit.count] for hit in result.hits]
    # `out` is written by hand so that the redacted value keeps the order of its keys.
    return (
        f'{{"id":{compact(request["id"])},"out":{compact(result.value)},'
        f'"hits":{compact(hits)},"error":{compact(result.error)}}}'
    )


def main() -> None:
    sys.stdout.write(compact({"capabilities": capabilities()}) + "\n")
    sys.stdout.flush()  # the driver waits for this line before it sends anything
    for line in sys.stdin:
        if line.strip():
            sys.stdout.write(respond(json.loads(line)) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
