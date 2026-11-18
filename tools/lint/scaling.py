"""Scaling run (Python re, ASCII): same contract as scaling.ts."""
import json
import re
import sys
import time

payload = json.load(sys.stdin)
results = []
for item in payload["patterns"]:
    pattern = re.compile(item["source"], re.ASCII)
    for attack in payload["attacks"]:
        for size in payload["sizes"]:
            unit = attack["unit"]
            text = (unit * (size // len(unit) + 1))[:size]
            best = float("inf")
            for _ in range(payload["runs"]):
                started = time.perf_counter()
                for _match in pattern.finditer(text):
                    pass
                best = min(best, (time.perf_counter() - started) * 1000)
            results.append({"where": item["where"], "attack": attack["name"], "size": size, "ms": best})
json.dump(results, sys.stdout)
