"""Command-line front end for the Python MiMC reference.

Examples:
    python -m mimc --field bls12_381_fr --rounds 8 --x 42
    python -m mimc --field pasta_fp --rounds 1024 --x 0xff
"""

from __future__ import annotations

import argparse
import sys

from . import EXPONENT, MAX_ROUNDS, MODULI, load_params, mimc_hash


def _integer(text: str) -> int:
    """Parse a decimal or ``0x``-prefixed integer."""
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from None


def _rounds(text: str) -> int:
    """Parse a round count in ``1..MAX_ROUNDS`` that is a power of two."""
    value = _integer(text)
    if not 1 <= value <= MAX_ROUNDS:
        raise argparse.ArgumentTypeError(
            f"round count must be in 1..{MAX_ROUNDS}, got {value}"
        )
    if value & (value - 1):
        raise argparse.ArgumentTypeError(
            f"round count must be a power of two, got {value}"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m mimc",
        description="Evaluate the MiMC reference implementation.",
    )
    parser.add_argument(
        "--field",
        required=True,
        choices=sorted(MODULI),
        help="native scalar field of the target proof system",
    )
    parser.add_argument(
        "--rounds",
        required=True,
        type=_rounds,
        help=f"number of rounds r, a power of two up to {MAX_ROUNDS}",
    )
    parser.add_argument(
        "--x",
        required=True,
        type=_integer,
        help="input field element, decimal or 0x-prefixed",
    )
    parser.add_argument(
        "--exponent",
        type=_integer,
        default=EXPONENT,
        help=f"round-function exponent e (default: {EXPONENT})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, evaluate MiMC and print the decimal result."""
    parser = build_parser()
    args = parser.parse_args(argv)

    modulus = MODULI[args.field]
    if not 0 <= args.x < modulus:
        parser.error(f"--x must be in 0..{modulus - 1}")

    if args.exponent < 2:
        parser.error("--exponent must be at least 2")

    params = load_params(
        args.field,
        args.rounds,
        exponent=args.exponent,
    )
    print(mimc_hash(params, args.x))
    return 0


if __name__ == "__main__":
    sys.exit(main())
