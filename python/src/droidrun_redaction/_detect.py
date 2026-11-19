"""Standard-tier detection (SPEC 4.10) and the hit merge and splice (SPEC section 7)."""

from typing import Any

from . import _full_rules, _rules
from ._patterns import Range
from ._placeholder import build_read_placeholder
from ._spec import RULES, SpecError

Hit = tuple[str, int, int]

_PREPARE = {
    "regex": _rules.prepare_regex,
    "dotted-token": _rules.prepare_dotted_token,
    "pem-blocks": _rules.prepare_pem_blocks,
    "cookie-lines": _rules.prepare_cookie_lines,
    "auth-values": _rules.prepare_auth_values,
    "keyword-pairs": _rules.prepare_keyword_pairs,
    "quoted-pairs": _rules.prepare_quoted_pairs,
    "unquoted-pairs": _rules.prepare_unquoted_pairs,
    "query-values": _rules.prepare_query_values,
}


def _prepare(rule: dict[str, Any], table: dict[str, Any]) -> tuple[str, _rules.Scanner]:
    prepare = table.get(rule["kind"])
    if prepare is None:
        raise SpecError("redaction spec holds an unknown rule kind")
    return rule["id"], prepare(rule)


_PIPELINE = [_prepare(rule, _PREPARE) for rule in RULES["pipeline"]]

_FULL_PREPARE = {
    "regex": _rules.prepare_regex,
    "token": _full_rules.prepare_token,
    "dash-chain": _full_rules.prepare_dash_chain,
    "sendgrid-key": _full_rules.prepare_sendgrid_key,
    "pem-key": _full_rules.prepare_pem_key,
    "credential-uri": _full_rules.prepare_credential_uri,
}


_FULL_PIPELINE = [_prepare(rule, _FULL_PREPARE) for rule in RULES["full"]]


def merge_hits(hits: list[Hit]) -> list[Hit]:
    """Sort by start (equal starts keep their order), then fold overlapping or touching ranges (SPEC 7)."""
    merged: list[Hit] = []
    for rule_id, start, end in sorted(hits, key=lambda hit: hit[1]):
        if merged and start <= merged[-1][2]:
            last_id, last_start, last_end = merged[-1]
            merged[-1] = (last_id, last_start, max(last_end, end))
        else:
            merged.append((rule_id, start, end))
    return merged


def _collect(entries: list[tuple[str, _rules.Scanner]], units: str) -> list[Hit]:
    """Every rule of the list over the text, in order, each range tagged with its rule id."""
    hits: list[Hit] = []
    for rule_id, scan in entries:
        ranges: list[Range] = scan(units)
        hits.extend((rule_id, start, end) for start, end in ranges)
    return hits


def detect(units: str) -> list[Hit]:
    """The merged hits of the standard rules over the whole unit string."""
    return merge_hits(_collect(_PIPELINE, units))


def detect_full_rules(units: str) -> list[Hit]:
    """The hits of the full-tier rules over one unit string (no windows), by start, then end (SPEC 4.17)."""
    return sorted(_collect(_FULL_PIPELINE, units), key=lambda hit: (hit[1], hit[2]))


def splice(units: str, hits: list[Hit]) -> str:
    """The text with every (merged) hit replaced by its read placeholder."""
    parts: list[str] = []
    cursor = 0
    for rule_id, start, end in hits:
        parts.append(units[cursor:start])
        parts.append(build_read_placeholder(rule_id))
        cursor = end
    parts.append(units[cursor:])
    return "".join(parts)
