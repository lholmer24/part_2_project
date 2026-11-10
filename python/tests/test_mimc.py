"""Tests for the Python MiMC reference.

The known-answer vectors are the same values that the Rust tests in
``crates/mimc/tests/mimc.rs`` pin, so a change to either implementation shows up
on both sides.
"""

from __future__ import annotations

import math

import pytest

from mimc import (
    EXPONENT,
    MAX_ROUNDS,
    MODULI,
    load_params,
    load_round_constants,
    mimc_hash,
)

FIELDS = sorted(MODULI)
ROUND_COUNTS = [1, 2, 4, 8, 16]
INPUTS = [0, 1, 2, 12345]

#: Known answers as ``(rounds, x, expected hash)``. The first entry is
#: ``c_0^5 mod q``, the second is ``(1 + c_0)^5 + 1`` and the third chains two
#: rounds with ``x = 12345``. Each value can be recomputed by hand from the
#: committed round constants.
KNOWN_ANSWERS: dict[str, tuple[tuple[int, int, int], ...]] = {
    "bls12_381_fr": (
        (1, 0, 31256827246040939561577844704640754034563723088148309880838383269002778408470),
        (1, 1, 18429270801925526510315227970385121513146206612125632435847666342457270912254),
        (2, 12345, 26047206175063726665032477906411648087677110868748662324746339405666930686596),
    ),
    "pasta_fp": (
        (1, 0, 22108229207804449142020689367364205987107508651908394374992996221051925855474),
        (1, 1, 19582859191974796830789326816557905652037678524480172858520631355877071627533),
        (2, 12345, 17041585443435438133225427702512636541011581402532836815961170488119809389496),
    ),
    "ristretto255_scalar": (
        (1, 0, 445784415943337186979121204367215484538833569375727123310245689540472579067),
        (1, 1, 5732735298174027152461658965650303852087823268112529167335208166243903155792),
        (2, 12345, 4907682761964298974374603438303417080282842053421983791442174171090796047345),
    ),
    "winterfell_f128": (
        (1, 0, 47658069912918930360376387994620023688),
        (1, 1, 301435011788671344824403183502175143614),
        (2, 12345, 139934522587202667554541012347463374648),
    ),
}


@pytest.mark.parametrize("field", FIELDS)
def test_exponent_is_a_permutation(field: str) -> None:
    assert math.gcd(EXPONENT, MODULI[field] - 1) == 1


@pytest.mark.parametrize("field", FIELDS)
def test_constant_file_is_in_range(field: str) -> None:
    constants = load_round_constants(field, MAX_ROUNDS)
    assert len(constants) == MAX_ROUNDS
    assert all(0 <= c < MODULI[field] for c in constants)


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("rounds", ROUND_COUNTS)
def test_loaded_params_shape(field: str, rounds: int) -> None:
    params = load_params(field, rounds)
    assert params.modulus == MODULI[field]
    assert params.rounds == rounds
    assert params.exponent == EXPONENT
    assert len(params.round_constants) == rounds


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("rounds", ROUND_COUNTS)
@pytest.mark.parametrize("x", INPUTS)
def test_output_is_a_field_element(field: str, rounds: int, x: int) -> None:
    params = load_params(field, rounds)
    assert 0 <= mimc_hash(params, x) < MODULI[field]


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("rounds", ROUND_COUNTS)
def test_hash_is_deterministic(field: str, rounds: int) -> None:
    params = load_params(field, rounds)
    assert mimc_hash(params, 12345) == mimc_hash(params, 12345)


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("rounds", ROUND_COUNTS)
def test_hash_depends_on_input(field: str, rounds: int) -> None:
    params = load_params(field, rounds)
    assert mimc_hash(params, 0) != mimc_hash(params, 1)


@pytest.mark.parametrize(
    ("field", "rounds", "x", "expected"),
    [
        (field, rounds, x, expected)
        for field, vectors in KNOWN_ANSWERS.items()
        for rounds, x, expected in vectors
    ],
)
def test_known_answers(field: str, rounds: int, x: int, expected: int) -> None:
    params = load_params(field, rounds)
    assert mimc_hash(params, x) == expected


@pytest.mark.parametrize("field", FIELDS)
def test_one_round_matches_the_definition(field: str) -> None:
    modulus = MODULI[field]
    (constant,) = load_round_constants(field, 1)
    params = load_params(field, 1)
    x = 12345
    expected = (pow(x + constant, EXPONENT, modulus) + x) % modulus
    assert mimc_hash(params, x) == expected
