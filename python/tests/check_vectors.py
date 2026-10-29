#!/usr/bin/env python3
"""Check Rust MiMC vectors against the Python reference.

Reads one vector per line from stdin:

    <field> <rounds> <x> <hash in hex>

Exits zero when every vector matches, and one on the first mismatch. This
script is test scaffolding; it calls :func:`mimc.mimc_hash`.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mimc import load_params, mimc_hash


def main() -> int:
    checked = 0
    for number, line in enumerate(sys.stdin, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        field, rounds_text, x_text, hash_text = line.split()
        params = load_params(field, int(rounds_text))
        want = mimc_hash(params, int(x_text))
        got = int(hash_text, 16)
        if got != want:
            print(f"mismatch on line {number}: {line}", file=sys.stderr)
            print(f"  rust = {got}", file=sys.stderr)
            print(f"  python = {want}", file=sys.stderr)
            return 1
        checked += 1

    if checked == 0:
        print("no vectors on stdin", file=sys.stderr)
        return 1

    print(f"checked {checked} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
