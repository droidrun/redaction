"""The `ipv6` check of the `regex` rule (SPEC 5.8): is a run of hex digits and colons an IPv6 address."""

import re

_HEX_GROUP = re.compile("[0-9A-Fa-f]{1,4}", re.ASCII)
_GROUPS = 8


def _are_groups(part: str) -> bool:
    return all(_HEX_GROUP.fullmatch(group) is not None for group in part.split(":"))


def _side_groups(side: str) -> float:
    """The groups on one side of `::`: none for an empty side, else every group must be valid."""
    if side == "":
        return 0
    return len(side.split(":")) if _are_groups(side) else float("inf")


def is_ipv6(text: str, min_colons: int) -> bool:
    """`min_colons` is how many colons the text needs at least (a bare text needs more than a bracketed one)."""
    if text.count(":") < min_colons:
        return False
    parts = text.split("::")
    if len(parts) == 1:
        return text.count(":") == _GROUPS - 1 and _are_groups(text)
    if len(parts) != 2:
        return False
    return _side_groups(parts[0]) + _side_groups(parts[1]) < _GROUPS
