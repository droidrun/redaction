"""Compile every pattern with Python's re (ASCII mode, warnings as errors). Reads a JSON list from stdin."""
import json
import re
import sys
import warnings

warnings.simplefilter("error")
failures = []
for item in json.load(sys.stdin):
    try:
        re.compile(item["source"], re.ASCII)
    except (re.error, Warning) as error:
        failures.append({"where": item["where"], "error": type(error).__name__})
json.dump(failures, sys.stdout)
