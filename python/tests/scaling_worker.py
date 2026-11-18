"""Subprocess of test_scaling: runs `redact_text` over attack strings and prints the times."""

import json
import sys
import time

from droidrun_redaction import redact_text

payload = json.load(sys.stdin)
results = []
for attack in payload["attacks"]:
    unit = attack["unit"]
    for size in payload["sizes"]:
        text = (unit * (size // len(unit) + 1))[:size]
        started = time.perf_counter()
        redact_text(text, mode="strict", max_chars=10**9)
        results.append({"attack": attack["name"], "size": size, "ms": (time.perf_counter() - started) * 1000})
json.dump(results, sys.stdout)
