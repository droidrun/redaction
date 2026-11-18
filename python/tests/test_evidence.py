"""log2 and entropy (SPEC 5.4): the table of the spec holds the output of Node for these arguments."""

import pytest
from droidrun_redaction._evidence import log2_fdlibm, shannon_entropy
from droidrun_redaction._units import to_units


@pytest.mark.parametrize(
    ("numerator", "denominator", "expected"),
    [
        (1, 3, -1.5849625007211563),
        (1, 7, -2.807354922057604),
        (2, 9, -2.1699250014423126),
        (3, 22, -2.8744691179161412),
        (5, 13, -1.3785116232537298),
        (3, 17, -2.502500340529183),
        (1, 1000003, -19.931572897402805),
        (1, 22, -4.459431618637297),
        (7, 44, -2.652076696579693),
        (1, 13, -3.700439718141092),
        (1, 10, -3.321928094887362),
        (3, 4, -0.4150374992788438),
        (11, 29, -1.398549376490275),
        (17, 19, -0.1604646721932461),
    ],
)
def test_log2_gives_the_value_node_gives(numerator, denominator, expected):
    assert log2_fdlibm(numerator / denominator) == expected


def test_log2_of_one_is_zero():
    assert log2_fdlibm(1.0) == 0.0


def test_entropy_of_the_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_divides_by_the_length_in_units():
    # four distinct astral characters: 4 symbols in 8 units, each p = 1/8 (not 1/4)
    assert shannon_entropy(to_units("\U0001f600\U0001f601\U0001f602\U0001f603")) == 1.5


def test_entropy_of_distinct_symbols():
    assert shannon_entropy("abcdefgh") == 3.0


def test_entropy_uses_the_log2_of_node():
    # A platform log2 gives 1.483659164397962... for these counts on some systems; Node gives this value.
    assert shannon_entropy("bbcaaabacacabbbaa") == 1.4836591643979624
