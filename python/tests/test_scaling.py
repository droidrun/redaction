"""Scaling (SPEC section 10.5): attack strings through `redact_text` at 100 KB and 1 MB.

The attack units come from tools/lib/attacks.ts (run by bun). Each worker is a subprocess under an external
deadline. The time at 1 MB must not exceed 30 times the time at 100 KB (floor 10 ms) and 10 s absolute.
"""

import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
SIZES = [100_000, 1_000_000]
WORKERS = 4
DEADLINE_SECONDS = 900
RATIO_LIMIT = 30
FLOOR_MS = 10
ABSOLUTE_LIMIT_MS = 10_000


def load_attacks():
    bun = shutil.which("bun")
    if bun is None and os.environ.get("CI") is None:
        pytest.skip("bun is not installed (CI always runs this test)")
    assert bun is not None, "bun is required to generate the attack strings"
    output = subprocess.run(
        [bun, str(TESTS / "attacks.ts")], check=True, capture_output=True, text=True, timeout=120
    ).stdout
    return json.loads(output)


def run_worker(attacks):
    """Run one worker on its share of the attacks under the external deadline; returns its timings."""
    completed = subprocess.run(
        [sys.executable, str(TESTS / "scaling_worker.py")],
        input=json.dumps({"attacks": attacks, "sizes": SIZES}),
        capture_output=True,
        text=True,
        timeout=DEADLINE_SECONDS,
    )
    assert completed.returncode == 0
    return json.loads(completed.stdout)


def test_time_grows_linearly_with_the_input():
    attacks = load_attacks()
    slices = [attacks[index::WORKERS] for index in range(WORKERS)]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = [row for rows in pool.map(run_worker, slices) for row in rows]
    times = {(row["attack"], row["size"]): row["ms"] for row in results}
    assert len(times) == len(attacks) * len(SIZES)
    slow = []
    for attack in attacks:
        small = times[(attack["name"], SIZES[0])]
        large = times[(attack["name"], SIZES[1])]
        if large > RATIO_LIMIT * max(small, FLOOR_MS) or large > ABSOLUTE_LIMIT_MS:
            slow.append(attack["name"])
    assert slow == []
