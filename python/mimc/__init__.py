"""Reference MiMC implementation for the Part II benchmark.

Field parameters and round constants follow ``params/PARAMS.md`` and
``params/round_constants/``. :func:`mimc_hash` returns the public hash
``E(x) + x``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "EXPONENT",
    "MAX_ROUNDS",
    "MODULI",
    "ROUND_CONSTANT_DIR",
    "MimcParams",
    "load_params",
    "load_round_constants",
    "mimc_hash",
    "round_function",
]

#: Native scalar-field modulus of each system. Systems that share a field
#: share an entry and a round-constant file.
MODULI: dict[str, int] = {
    "bls12_381_fr": 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
    "ristretto255_scalar": 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED,
    "pasta_fp": 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001,
    "winterfell_f128": 0xFFFFFFFFFFFFFFFFFFFFD30000000001,
}

#: Round-function exponent e. gcd(e, q - 1) = 1 in every field above.
EXPONENT: int = 5

#: The generated constant files hold 2^15 entries per field.
MAX_ROUNDS: int = 1 << 15

#: Directory holding ``<field>.txt``, one decimal element per line.
ROUND_CONSTANT_DIR: Path = (
    Path(__file__).resolve().parents[2] / "params" / "round_constants"
)


@dataclass(frozen=True)
class MimcParams:
    """MiMC parameters for one field and one round count.

    Attributes:
        field: Key into :data:`MODULI`.
        modulus: Field modulus q.
        rounds: Number of rounds r.
        exponent: Round-function exponent e.
        round_constants: c_0, ..., c_{r-1}.
    """

    field: str
    modulus: int
    rounds: int
    exponent: int
    round_constants: tuple[int, ...]


def load_round_constants(field: str, rounds: int) -> tuple[int, ...]:
    """Load the first ``rounds`` constants for ``field``.

    Args:
        field: Key into :data:`MODULI`.
        rounds: Number of constants to read.

    Returns:
        The constants c_0, ..., c_{rounds-1} as Python integers.

    Raises:
        KeyError: ``field`` is not a known field name.
        ValueError: ``rounds`` is outside ``1..MAX_ROUNDS``.
        FileNotFoundError: The constant file is missing.
    """
    if field not in MODULI:
        raise KeyError(f"unknown field: {field!r}")
    if not 1 <= rounds <= MAX_ROUNDS:
        raise ValueError(f"rounds must be in 1..{MAX_ROUNDS}, got {rounds}")

    path = ROUND_CONSTANT_DIR / f"{field}.txt"
    with path.open("r", encoding="ascii") as handle:
        constants = []
        for line in handle:
            if len(constants) == rounds:
                break
            line = line.strip()
            if line:
                constants.append(int(line))
    if len(constants) != rounds:
        raise ValueError(
            f"{path} holds {len(constants)} constants, expected at least {rounds}"
        )
    return tuple(constants)


def load_params(
    field: str,
    rounds: int,
    exponent: int = EXPONENT,
) -> MimcParams:
    """Build a :class:`MimcParams` from the shared parameter files.

    Args:
        field: Key into :data:`MODULI`.
        rounds: Number of rounds r.
        exponent: Round-function exponent e.

    Returns:
        Parameters with the constants loaded for this field and round count.
    """
    if field not in MODULI:
        raise KeyError(f"unknown field: {field!r}")
    return MimcParams(
        field=field,
        modulus=MODULI[field],
        rounds=rounds,
        exponent=exponent,
        round_constants=load_round_constants(field, rounds),
    )


def round_function(
    state: int,
    constant: int,
    exponent: int,
    modulus: int,
) -> int:
    """Apply one MiMC round to ``state``.

    Args:
        state: Current field element.
        constant: Round constant c_i.
        exponent: Exponent e.
        modulus: Field modulus q.

    Returns:
        The next field element, in ``0..q``.
    """
    return pow(state + constant, exponent, modulus)


def mimc_hash(params: MimcParams, x: int) -> int:
    """Compute the public hash ``E(x) + x``.

    Args:
        params: Field, round count, exponent and round constants.
        x: Input field element, in ``0..q``.

    Returns:
        The public hash as a Python integer.
    """
    state = x
    for i in range(params.rounds):
        state = round_function(state, params.round_constants[i], params.exponent, params.modulus)
    return (state + x) % params.modulus
