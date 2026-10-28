#!/usr/bin/env python3
"""Generate the MiMC round constants read by the Rust code.

Each output file contains one decimal field element per line. Systems that
share a scalar field share the file. See params/PARAMS.md for the round-count
sweep.
"""

import random
from pathlib import Path

SEED = "zk-SNARK"
COUNT = 1 << 15
OUT_DIR = Path(__file__).resolve().parents[1] / "params" / "round_constants"

FIELDS = {
    "bls12_381_fr": 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
    "ristretto255_scalar": 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED,
    "pasta_fp": 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001,
    "winterfell_f128": 0xFFFFFFFFFFFFFFFFFFFFD30000000001,
}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)

    for field_name, modulus in FIELDS.items():
        constants = [rng.randrange(modulus) for _ in range(COUNT)]
        path = OUT_DIR / f"{field_name}.txt"
        path.write_text("\n".join(map(str, constants)) + "\n", encoding="ascii")
        print(f"wrote {COUNT} constants to {path}")


if __name__ == "__main__":
    main()
