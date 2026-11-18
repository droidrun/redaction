"""Key names (SPEC section 6): which object keys name a secret."""

from functools import lru_cache

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


def _is_upper(unit: str) -> bool:
    return "A" <= unit <= "Z"


def _is_lower(unit: str) -> bool:
    return "a" <= unit <= "z"


def _is_digit(unit: str) -> bool:
    return "0" <= unit <= "9"


def _run_end(key: str, start: int, test) -> int:
    end = start
    while end < len(key) and test(key[end]):
        end += 1
    return end


def _word_end(key: str, start: int) -> int:
    """End of the word that starts at `start`, or `start` when none does."""
    unit = key[start]
    if _is_upper(unit):
        capitals = _run_end(key, start, _is_upper)
        follower = key[capitals : capitals + 1]
        if follower == "" or not _is_lower(follower):
            return capitals
        if capitals - start >= 2:
            return capitals - 1
    lower_start = start + 1 if _is_upper(unit) else start
    lower_end = _run_end(key, lower_start, _is_lower)
    if lower_end > lower_start:
        return lower_end
    return _run_end(key, start, _is_digit) if _is_digit(unit) else start


def split_key_words(key: str) -> list[str]:
    """`clientSecret` gives `client secret`, `APIKey` gives `api key`, `x-auth-token` gives `x auth token`."""
    words: list[str] = []
    at = 0
    while at < len(key):
        end = _word_end(key, at)
        if end == at:
            at += 1
            continue
        words.append(key[at:end].lower())
        at = end
    return words


def _compact_key(key: str) -> str:
    folded = fold_lower(key).replace("İ", "i")
    return "".join(unit for unit in folded if _is_lower(unit) or _is_digit(unit))


def _is_secret_word(word: str, plural: bool) -> bool:
    base = word.removesuffix("s") if plural else word
    if word in _JOINED or base in _JOINED:
        return True
    if any(base.endswith(suffix) for suffix in _SUFFIX_WORDS):
        return True
    return any(word.startswith(prefix) for prefix in _PREFIX_WORDS)


def _word_matches(word: str | None, expected: str, plural: bool) -> bool:
    return word == expected or (plural and word == expected + "s")


def _starts_sequence(words: list[str], start: int, sequence: list[str], plural: bool) -> bool:
    for offset, expected in enumerate(sequence):
        word = words[start + offset] if start + offset < len(words) else None
        if not _word_matches(word, expected, plural):
            return False
    return True


@lru_cache(maxsize=2048)
def _match_key(key: str, plural: bool) -> bool:
    """Pure in its arguments, and the same few keys come back again and again, so results are cached."""
    words = split_key_words(key)
    if _compact_key(key) in _EXACT_KEYS:
        return True
    if words and words[-1] == _PASS_LAST_WORD:
        return True
    if any(_is_secret_word(word, plural) for word in words):
        return True
    return any(
        _starts_sequence(words, start, sequence, plural)
        for sequence in _SEQUENCES
        for start in range(len(words))
    )


def is_secret_key_name(key: str) -> bool:
    """True for names such as `apiKey`, `client_secret`, `x-auth-token`, `Set-Cookie`, `pin`, `tokens`."""
    return _match_key(key, True)


def key_verdict(raw_key: str) -> str:
    """What a key makes of the values below it: `none`, `string` (strings only) or `any` (numbers too)."""
    key = " ".join(literal_segments(raw_key)) if PLACEHOLDER_MARK in raw_key else raw_key
    if not _match_key(key, True):
        return "none"
    if not _match_key(key, False):
        return "string"
    return "string" if any(word in _COUNT_WORDS for word in split_key_words(key)) else "any"


def stronger_verdict(first: str, second: str) -> str:
    """The stronger of two verdicts: a nested secret key never weakens the context."""
    if first == "any" or second == "any":
        return "any"
    return "string" if first == "string" or second == "string" else "none"
