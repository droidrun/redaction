"""Scaling (SPEC section 10.5): attack strings through `redact_text` at 100 KB and 1 MB, and long JSON keys.

The attack units come from tools/lib/attacks.ts (run by bun), among them a PEM header whose body stops at
once and a query value followed by a space. Each worker is a subprocess
under an external deadline. The time at 1 MB must not exceed 15 times the time at 100 KB (floor 10 ms; linear
growth is 10 times). A first pass runs the attacks in parallel; every attack that fails the ratio there is
measured again alone, one at a time, best of three, because a loaded machine skews a single run.
"""

import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from droidrun_redaction import redact_json

TESTS = Path(__file__).resolve().parent
SIZES = [100_000, 1_000_000]
WORKERS = os.cpu_count() or 2
DEADLINE_SECONDS = 900
RATIO_LIMIT = 15
FLOOR_MS = 10
REPEATS = 3
LONG_KEY_LIMIT_SECONDS = 2.0


def load_attacks():
    bun = shutil.which("bun")
    if bun is None and os.environ.get("CI") is None:
        pytest.skip("bun is not installed (CI always runs this test)")
    assert bun is not None, "bun is required to generate the attack strings"
    output = subprocess.run(
        [bun, str(TESTS / "attacks.ts")], check=True, capture_output=True, text=True, timeout=120
    ).stdout
    return json.loads(output)


def run_worker(attacks, runs):
    """Run one worker on its share of the attacks under the external deadline; returns its timings."""
    completed = subprocess.run(
        [sys.executable, str(TESTS / "scaling_worker.py")],
        input=json.dumps({"attacks": attacks, "sizes": SIZES, "runs": runs}),
        capture_output=True,
        text=True,
        timeout=DEADLINE_SECONDS,
    )
    assert completed.returncode == 0
    return json.loads(completed.stdout)


def too_slow(rows):
    """The attack names whose time at the large size is above the ratio limit."""
    times = {(row["attack"], row["size"]): row["ms"] for row in rows}
    return [
        name
        for name in {row["attack"] for row in rows}
        if times[(name, SIZES[1])] > RATIO_LIMIT * max(times[(name, SIZES[0])], FLOOR_MS)
    ]


def test_time_grows_linearly_with_the_input():
    attacks = load_attacks()
    slices = [attacks[index::WORKERS] for index in range(WORKERS)]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        first_pass = [row for rows in pool.map(lambda part: run_worker(part, 1), slices) for row in rows]
    assert len(first_pass) == len(attacks) * len(SIZES)
    suspects = set(too_slow(first_pass))
    slow = []
    for attack in attacks:
        if attack["name"] in suspects:
            slow.extend(too_slow(run_worker([attack], REPEATS)))
    assert slow == []


@pytest.mark.parametrize("mode", ["strict", "compat"])
def test_long_keys_are_cheap(mode):
    unit = "ab_Cd-"
    many = {f"k{index}_" + unit * 1700: "v" for index in range(200)}
    one_big = {unit * 340_000: "v"}
    for value in (many, one_big):
        started = time.perf_counter()
        redact_json(value, mode=mode, max_chars=10**9)
        assert time.perf_counter() - started < LONG_KEY_LIMIT_SECONDS
