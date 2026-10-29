"""Test scaffolding for the Python MiMC reference.

The hash tests fail until :func:`mimc.mimc_hash` has a body. The parameter and
constant-file tests pass already because they only check the shared data.
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
