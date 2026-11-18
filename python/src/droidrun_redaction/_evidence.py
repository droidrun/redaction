"""Value evidence (SPEC section 5.4), trivial values and stand-ins (5.5)."""

import re
import struct
from collections import Counter

from ._patterns import char_test, contains_test, fold_lower, run_pattern
from ._placeholder import is_whole_placeholder
from ._spec import ALGORITHMS

_EVIDENCE = ALGORITHMS["evidence"]
_TRIVIAL = ALGORITHMS["trivial"]
_DOC = ALGORITHMS["docPlaceholder"]

_CLASS_TESTS = [contains_test(pattern) for pattern in _EVIDENCE["classes"]]
_TRIVIAL_WORDS = frozenset(_TRIVIAL["words"])
_INNER_UNITS = run_pattern(_TRIVIAL["wrapperInner"])
_DOC_SEPARATOR = char_test(_DOC["separator"])
_IS_SPACE = char_test("[{{WS}}]")
_SURROGATE = re.compile("[\ud800-\udfff]")
_SYMBOLS = re.compile("[\ud800-\udbff][\udc00-\udfff]|[\\s\\S]")

# fdlibm `__ieee754_log2` (FreeBSD e_log2.c, with k_log1p), the function V8 uses for `Math.log2`.
_IVLN2_HI = 1.44269504072144627571e00
_IVLN2_LO = 1.67517131648865118353e-10
_LG1 = 6.666666666666735130e-01
_LG2 = 3.999999999940941908e-01
_LG3 = 2.857142874366239149e-01
_LG4 = 2.222219843214978396e-01
_LG5 = 1.818357216161805012e-01
_LG6 = 1.531383769920937332e-01
_LG7 = 1.479819860511658591e-01


def _words_of(value: float) -> tuple[int, int]:
    bits = struct.unpack("<Q", struct.pack("<d", value))[0]
    return bits >> 32, bits & 0xFFFFFFFF


def _from_words(high: int, low: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", (high << 32) | low))[0]


def _k_log1p(f: float) -> float:
    s = f / (2.0 + f)
    z = s * s
    w = z * z
    t1 = w * (_LG2 + w * (_LG4 + w * _LG6))
    t2 = z * (_LG1 + w * (_LG3 + w * (_LG5 + w * _LG7)))
    r = t2 + t1
    hfsq = 0.5 * f * f
    return s * (hfsq + r)


def log2_fdlibm(x: float) -> float:
    """`log2` for a normal double `0 < x < inf`, bit for bit what V8 returns."""
    high, low = _words_of(x)
    if high == 0x3FF00000 and low == 0:
        return 0.0
    k = (high >> 20) - 1023
    high &= 0x000FFFFF
    i = (high + 0x95F64) & 0x100000
    x = _from_words(high | (i ^ 0x3FF00000), low)
    k += i >> 20
    y = float(k)
    f = x - 1.0
    hfsq = 0.5 * f * f
    r = _k_log1p(f)
    hi = f - hfsq
    hi = _from_words(_words_of(hi)[0], 0)
    lo = (f - hi) - hfsq + r
    val_hi = hi * _IVLN2_HI
    val_lo = (lo + hi) * _IVLN2_LO + lo * _IVLN2_HI
    w = y + val_hi
    val_lo += (y - w) + val_hi
    return val_lo + w


def shannon_entropy(units: str) -> float:
    """Entropy of a unit string: symbols are code points, the divisor is the length in units."""
    length = len(units)
    if length == 0:
        return 0.0
    symbols = units if _SURROGATE.search(units) is None else _SYMBOLS.findall(units)
    entropy = 0.0
    for count in Counter(symbols).values():
        probability = count / length
        entropy = entropy - probability * log2_fdlibm(probability)
    return entropy


def trim(text: str) -> str:
    """Remove the spec's whitespace set from both ends."""
    start = 0
    end = len(text)
    while start < end and _IS_SPACE(text[start]):
        start += 1
    while end > start and _IS_SPACE(text[end - 1]):
        end -= 1
    return text[start:end]


def _is_mask(value: str) -> bool:
    return value != "" and any(value == mask * len(value) for mask in _TRIVIAL["maskChars"])


def _is_wrapped(value: str) -> bool:
    if len(value) < 2:
        return False
    for opening, closing in _TRIVIAL["wrappers"]:
        is_wrapper = value.startswith(opening) and value.endswith(closing)
        if is_wrapper and _INNER_UNITS.fullmatch(value, 1, len(value) - 1) is not None:
            return True
    return False


def is_trivial_value(raw: str) -> bool:
    """Deny-listed stand-ins: `null`, `changeme`, `xxxxxxxx`, `********`, `<placeholder>`, `{{secret}}`."""
    value = fold_lower(trim(raw))
    return value in _TRIVIAL_WORDS or _is_mask(value) or _is_wrapped(value)


def is_doc_placeholder(raw: str) -> bool:
    """Documentation-style stand-ins (`your_api_key_here`, `REPLACE_ME_TOKEN`)."""
    value = fold_lower(trim(raw))
    for prefix in _DOC["prefixes"]:
        follower = value[len(prefix) : len(prefix) + 1]
        if value.startswith(prefix) and follower != "" and _DOC_SEPARATOR(follower):
            return True
    for suffix in _DOC["suffixes"]:
        at = len(value) - len(suffix) - 1
        if at >= 0 and value.endswith(suffix) and _DOC_SEPARATOR(value[at]):
            return True
    return False


def _strip_quotes(raw: str) -> str:
    quotes = _EVIDENCE["quoteChars"]
    without_leading = raw[1:] if raw != "" and raw[0] in quotes else raw
    if without_leading != "" and without_leading[-1] in quotes:
        return without_leading[:-1]
    return without_leading


def has_value_evidence(raw: str) -> bool:
    """At least `minClasses` character classes present, or enough entropy; stand-ins never count."""
    unquoted = _strip_quotes(raw)
    if is_whole_placeholder(unquoted) or is_trivial_value(unquoted):
        return False
    classes = sum(1 for test in _CLASS_TESTS if test(unquoted))
    if classes >= _EVIDENCE["minClasses"]:
        return True
    return shannon_entropy(unquoted) >= _EVIDENCE["entropyThreshold"]
