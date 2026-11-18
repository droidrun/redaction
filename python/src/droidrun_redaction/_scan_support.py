"""Small linear helpers the full-tier scanners share (SPEC 4.11, run memory).

Both keep state for ONE scan of ONE text, so a scanner makes them at the start of each call: the next
occurrence of any of a few literals (each literal searched forward only) and the end of a run of units of a
class, remembered for the run last measured (every start inside one run gets the same end for free).
"""

import re
from collections.abc import Callable, Sequence

from ._patterns import run_end

NextStart = Callable[[int], int]
RunEnd = Callable[[int], int]

_UNKNOWN = -2
_NONE = -1


def next_start_of(text: str, literals: Sequence[str]) -> NextStart:
    """The first position at or after `from` where one of `literals` starts, or -1. `from` never goes back."""
    remembered = [_UNKNOWN] * len(literals)

    def next_start(start: int) -> int:
        best = _NONE
        for index, literal in enumerate(literals):
            known = remembered[index]
            is_stale = known != _NONE and known < start
            found = text.find(literal, start) if known == _UNKNOWN or is_stale else known
            remembered[index] = found
            if found != _NONE and (best == _NONE or found < best):
                best = found
        return best

    return next_start


def cached_run_end(text: str, run: re.Pattern[str]) -> RunEnd:
    """End of the maximal run of the class that starts at `from` (`from` itself when there is none)."""
    low = 0
    high = 0

    def end_of(start: int) -> int:
        nonlocal low, high
        if low <= start < high:
            return high
        end = run_end(run, text, start)
        low = start
        high = end
        return end

    return end_of
