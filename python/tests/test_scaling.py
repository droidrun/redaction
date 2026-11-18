"""Scaling (SPEC section 10.5): attack strings through the full tier at 100 KB and 1 MB, and long JSON keys.

The attack units come from tools/lib/attacks.ts (run by bun): the standard and the full tier's prefixes,
separators and near misses, and composite attacks (a short cluster, then a long run: `ghs_1_` x 170, `.`,
`a` x N). Each worker is a subprocess under an external deadline. The time at 1 MB must not exceed 15 times
the time at 100 KB (floor 10 ms; linear growth is 10 times), and a composite attack at most 20 times the plain
text `aaa...` of its size (floor 20 ms). A first pass runs the attacks in parallel; every attack that fails
there is measured again with the plain text, one at a time, best of three, because a loaded machine skews a
single run. (Python measures a run with the C regex engine, so the cost of a run memory per class, which
SPEC 4.11 forbids, does not show in the time here; `test_full.py` counts the units the runs walk instead.)
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
WORKERS = int(os.environ.get("REDACTION_SCALING_WORKERS", os.cpu_count() or 2))
DEADLINE_SECONDS = 900
RATIO_LIMIT = 15
FLOOR_MS = 10
REPEATS = 3
COMPOSITE_FACTOR = 20
COMPOSITE_FLOOR_MS = 20
PLAIN = {"name": "__plain", "unit": "a"}
LONG_KEY_LIMIT_SECONDS = 2.0
COLLISION_LIMIT_SECONDS = 20.0
COLLISION_DEADLINE_SECONDS = 60


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


def too_slow(rows, composites):
    """The attacks whose time at the large size is above the ratio limit, or (a composite attack: a short
    cluster, then a long run) above `COMPOSITE_FACTOR` times the plain text of that size."""
    times = {(row["attack"], row["size"]): row["ms"] for row in rows}
    plain = max(times.get((PLAIN["name"], SIZES[1]), 0), COMPOSITE_FLOOR_MS)
    slow = []
    for name in {row["attack"] for row in rows} - {PLAIN["name"]}:
        small, large = max(times[(name, SIZES[0])], FLOOR_MS), times[(name, SIZES[1])]
        is_composite_slow = name in composites and large > COMPOSITE_FACTOR * plain
        if large > RATIO_LIMIT * small or is_composite_slow:
            slow.append(name)
    return slow


def test_time_grows_linearly_with_the_input():
    attacks = load_attacks()
    composites = {attack["name"] for attack in attacks if "head" in attack}
    assert len(composites) >= 1
    work = [PLAIN, *attacks]
    slices = [work[index::WORKERS] for index in range(WORKERS)]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        first_pass = [row for rows in pool.map(lambda part: run_worker(part, 1), slices) for row in rows]
    assert len(first_pass) == len(work) * len(SIZES)
    suspects = set(too_slow(first_pass, composites))
    slow = []
    for attack in attacks:
        if attack["name"] in suspects:
            slow.extend(too_slow(run_worker([PLAIN, attack], REPEATS), composites))
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


COLLISION_SNIPPET = """
import json, sys, time
from droidrun_redaction import redact_json

count, reserved_count = int(sys.argv[1]), int(sys.argv[2])
keys = {f"npm_{index:036d}".replace("0", "A"): index for index in range(count)}
reserved = {f"[REDACTED:npm#{number}]": number for number in range(2, reserved_count + 2)}
started = time.perf_counter()
out = redact_json({**reserved, **keys}, tier="full").value
print(json.dumps({"seconds": time.perf_counter() - started, "keys": list(out)}))
"""


def numbered_keys(count, reserved_count):
    """Redact `count` different tokens (one placeholder) beside `reserved_count` keys written as numbered
    placeholders, in a subprocess under an external deadline; returns (seconds, output keys)."""
    completed = subprocess.run(
        [sys.executable, "-c", COLLISION_SNIPPET, str(count), str(reserved_count)],
        capture_output=True,
        text=True,
        timeout=COLLISION_DEADLINE_SECONDS,
    )
    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    return result["seconds"], result["keys"]


def test_colliding_keys_are_numbered_in_linear_time():
    # 40,000 keys redact to one placeholder; a numbering that starts again at 2 for every key takes minutes.
    seconds, keys = numbered_keys(40_000, 0)
    assert seconds < COLLISION_LIMIT_SECONDS
    assert len(keys) == 40_000
    assert keys[:3] == ["[REDACTED:npm]", "[REDACTED:npm#2]", "[REDACTED:npm#3]"]
    assert keys[-1] == "[REDACTED:npm#40000]"


def test_numbering_skips_many_reserved_keys_in_linear_time():
    # 8,000 keys that are written as numbered placeholders are reserved; 8,000 tokens are numbered past them.
    seconds, keys = numbered_keys(8_000, 8_000)
    assert seconds < COLLISION_LIMIT_SECONDS
    assert len(keys) == 16_000
    assert "[REDACTED:npm]" in keys
    assert "[REDACTED:npm#8002]" in keys
