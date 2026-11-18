"""Key names (SPEC section 6): which object keys name a secret."""

import re
from functools import lru_cache
from typing import Literal

from ._patterns import fold_lower
from ._placeholder import PLACEHOLDER_MARK, literal_segments
from ._spec import KEYS

_SEQUENCES = [*KEYS["secretWords"], *KEYS["extraSequences"]]
_EXACT_KEYS = frozenset(KEYS["exactKeys"])
_JOINED = frozenset(
    ["".join(sequence) for sequence in _SEQUENCES if len(sequence) > 1] + list(KEYS["joinedExtra"])
)
_COUNT_WORDS = frozenset(KEYS["countWords"])
_SUFFIX_WORDS = tuple(KEYS["suffixWords"])
_PREFIX_WORDS = tuple(KEYS["prefixWords"])
_PASS_LAST_WORD = KEYS["passLastWord"]


# The word split of SPEC section 6 as one pattern: a run of capitals that no lower-case letter follows (a
# run followed by one gives back its last capital: backtracking), an optional capital and lower-case
# letters, digits.
_WORDS = re.compile("[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", re.ASCII)
_NOT_COMPACT = re.compile("[^a-z0-9]", re.ASCII)
# Keys longer than this are not cached: a cache entry keeps the whole (possibly secret) key alive.
_CACHE_LIMIT = 256

# The word sequences by their first word; with `plural` a first word also matches with a trailing `s`.
_BY_FIRST: dict[str, list[list[str]]] = {}
_BY_FIRST_PLURAL: dict[str, list[list[str]]] = {}
for _sequence in _SEQUENCES:
    _BY_FIRST.setdefault(_sequence[0], []).append(_sequence)
    _BY_FIRST_PLURAL.setdefault(_sequence[0], []).append(_sequence)
    _BY_FIRST_PLURAL.setdefault(_sequence[0] + "s", []).append(_sequence)


def split_key_words(key: str) -> list[str]:
    """`clientSecret` gives `client secret`, `APIKey` gives `api key`, `x-auth-token` gives `x auth token`."""
    return [word.lower() for word in _WORDS.findall(key)]


def _compact_key(key: str) -> str:
    return _NOT_COMPACT.sub("", fold_lower(key).replace("İ", "i"))


def _is_secret_word(word: str, plural: bool) -> bool:
    base = word.removesuffix("s") if plural else word
    if word in _JOINED or base in _JOINED:
        return True
    return base.endswith(_SUFFIX_WORDS) or word.startswith(_PREFIX_WORDS)


def _word_matches(word: str | None, expected: str, plural: bool) -> bool:
    return word == expected or (plural and word == expected + "s")


def _starts_sequence(words: list[str], start: int, sequence: list[str], plural: bool) -> bool:
    for offset, expected in enumerate(sequence):
        word = words[start + offset] if start + offset < len(words) else None
        if not _word_matches(word, expected, plural):
            return False
    return True


def _match_words(key: str, words: list[str], plural: bool) -> bool:
    if _compact_key(key) in _EXACT_KEYS:
        return True
    if words and words[-1] == _PASS_LAST_WORD:
        return True
    if any(_is_secret_word(word, plural) for word in words):
        return True
    by_first = _BY_FIRST_PLURAL if plural else _BY_FIRST
    return any(
        _starts_sequence(words, start, sequence, plural)
        for start, word in enumerate(words)
        for sequence in by_first.get(word, ())
    )


def _evaluate(key: str) -> tuple[bool, bool, bool]:
    """(matches as a plural, matches as a singular, holds a count word): one split of the key."""
    words = split_key_words(key)
    has_count_word = any(word in _COUNT_WORDS for word in words)
    return _match_words(key, words, True), _match_words(key, words, False), has_count_word


_evaluate_cached = lru_cache(maxsize=2048)(_evaluate)


def _evaluation(key: str) -> tuple[bool, bool, bool]:
    return _evaluate(key) if len(key) > _CACHE_LIMIT else _evaluate_cached(key)


def is_secret_key_name(key: str) -> bool:
    """True for names such as `apiKey`, `client_secret`, `x-auth-token`, `Set-Cookie`, `pin`, `tokens`."""
    return _evaluation(key)[0]


KeyVerdict = Literal["none", "string", "any"]


def key_verdict(key: str) -> KeyVerdict:
    """What a key makes of the values below it: `none`, `string` (strings only) or `any` (numbers too).

    A string under a `string` or `any` key is replaced; a number only under an `any` key (`pin`, `password`;
    not `max_tokens`, `prompt_tokens`). A key that was itself redacted is read without its placeholders.
    """
    text = " ".join(literal_segments(key)) if PLACEHOLDER_MARK in key else key
    matches_plural, matches_singular, has_count_word = _evaluation(text)
    if not matches_plural:
        return "none"
    return "string" if not matches_singular or has_count_word else "any"


def stronger_verdict(first: str, second: str) -> KeyVerdict:
    """The stronger of two verdicts: a nested secret key never weakens the context."""
    if first == "any" or second == "any":
        return "any"
    return "string" if first == "string" or second == "string" else "none"
