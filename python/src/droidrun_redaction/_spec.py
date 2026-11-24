"""The rule spec: loaded from the package data, checked against its hash, macros expanded.

The package refuses to import (and so processes no input) when a data file is missing, the hash
differs from the generated constant, the spec version is not supported or the rule set is empty.
Messages name the failure, never the data (SPEC section 12).
"""

import hashlib
import json
import re
from importlib import resources
from typing import Any

from ._spec_hash import SPEC_HASH

_SUPPORTED_VERSION = 1
_HASHED_FILES = ("rules.json", "keys.json", "algorithms.json")
_MACRO_REFERENCE = re.compile(r"\{\{([A-Z_]+)\}\}")
_MAX_MACRO_DEPTH = 8
_LETTER = re.compile("[a-z]")


class SpecError(RuntimeError):
    """The embedded spec is missing, altered or unusable."""


def _read_files() -> dict[str, bytes]:
    root = resources.files(__package__).joinpath("spec")
    try:
        return {name: root.joinpath(name).read_bytes() for name in _HASHED_FILES}
    except OSError:
        raise SpecError("redaction spec data is missing") from None


def _hash_of(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in _HASHED_FILES:
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(files[name])
        digest.update(b"\0")
    return digest.hexdigest()


def _checked(data: dict[str, Any]) -> dict[str, Any]:
    if data.get("specVersion") != _SUPPORTED_VERSION:
        raise SpecError("unsupported redaction spec version")
    return data


def _load() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    files = _read_files()
    if _hash_of(files) != SPEC_HASH:
        raise SpecError("redaction spec does not match its hash")
    try:
        rules, keys, algorithms = (_checked(json.loads(files[name])) for name in _HASHED_FILES)
    except ValueError:
        raise SpecError("redaction spec data is not valid") from None
    has_no_rules = any(len(rules.get(name, [])) == 0 for name in ("pipeline", "pii", "full"))
    if not isinstance(rules.get("strict"), list):
        raise SpecError("redaction spec holds no strict rules")
    if has_no_rules or len(keys.get("secretWords", [])) == 0:
        raise SpecError("redaction spec holds no rules")
    return rules, keys, algorithms


RULES, KEYS, ALGORITHMS = _load()


def _case_insensitive_char(char: str) -> str:
    return f"[{char}{char.upper()}]" if _LETTER.fullmatch(char) else char


def _expand_word_macro(macro: dict[str, Any]) -> str:
    sequences = macro["words"] if "fromKeys" not in macro else KEYS[macro["fromKeys"]]
    alternatives = [
        macro["join"].join("".join(_case_insensitive_char(c) for c in part) for part in words)
        for words in sequences
    ]
    return "(?:" + "|".join(alternatives) + ")"


def _expand_macro(name: str) -> str:
    macro = RULES["macros"].get(name)
    if macro is None:
        raise SpecError("redaction spec names an unknown macro")
    return macro if isinstance(macro, str) else _expand_word_macro(macro)


def expand_pattern(template: str, depth: int = 0) -> str:
    """The pattern with every `{{MACRO}}` replaced (macros may use other macros)."""
    if depth > _MAX_MACRO_DEPTH:
        raise SpecError("redaction spec macros nest too deep")
    expanded = _MACRO_REFERENCE.sub(lambda found: _expand_macro(found.group(1)), template)
    return expanded if expanded == template else expand_pattern(expanded, depth + 1)


def _matches_edit(rule: dict[str, Any], edit: dict[str, Any]) -> bool:
    is_id = "id" not in edit or rule["id"] == edit["id"]
    is_kind = "kind" not in edit or rule["kind"] == edit["kind"]
    return is_id and is_kind


def _apply_edit(rules: list[dict[str, Any]], edit: dict[str, Any]) -> list[dict[str, Any]]:
    targets = [rule for rule in rules if _matches_edit(rule, edit)]
    if not targets:
        raise SpecError("a strict edit of the spec matches no rule")
    if "add" in edit:
        if len(targets) != 1:
            raise SpecError("a strict edit that adds a rule must match one rule")
        at = next(index for index, rule in enumerate(rules) if rule is targets[0])
        return [*rules[: at + 1], edit["add"], *rules[at + 1 :]]
    return [{**rule, **edit["set"]} if _matches_edit(rule, edit) else rule for rule in rules]


def strict_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The `strict` rule list (SPEC 4.10): the `compat` list with the `strict` edits of the spec applied."""
    edited = list(rules)
    for edit in RULES["strict"]:
        edited = _apply_edit(edited, edit)
    return edited
