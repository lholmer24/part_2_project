# Who Knows? A Comparison of Zero-Knowledge Proof Systems

Part II project benchmarking Groth16, PLONK, Bulletproofs, STARK, Halo2 and
Spartan on a MiMC preimage statement.

## Layout

| Path | Purpose |
|---|---|
| `crates/mimc/` | Shared MiMC core, constants loader and field adapters |
| `crates/harness/` | Common setup/prove/verify interface, criterion timing and CSV output |
| `crates/groth16/` | Groth16 over BLS12-381 |
| `crates/plonk/` | PLONK over BLS12-381 |
| `crates/bulletproofs/` | Bulletproofs over Ristretto255 |
| `crates/stark/` | STARK over winterfell `f128` |
| `crates/halo2/` | Halo2 over Pasta |
| `crates/spartan/` | Spartan over Ristretto255 |
| `params/PARAMS.md` | Field, exponent, round-count and security parameters |
| `params/round_constants/` | Generated round constants, one file per field |
| `python/` | Python MiMC reference, constant generator and analysis |
| `results/` | Benchmark CSV output |
| `docs/` | Proposal and dissertation material |

## Requirements

- Rust 1.98.1, pinned in `rust-toolchain.toml` and installed with rustup
- Python 3.11 or newer

## Commands

```sh
cargo build
cargo test
cargo clippy --all-targets
cargo fmt --all -- --check

cd python
.venv/bin/python -m pytest
.venv/bin/python -m mimc --field bls12_381_fr --rounds 8 --x 42
```

The Python virtualenv lives in `python/.venv` and is not committed. Recreate it
with:

```sh
cd python
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

`python3 python/generate_round_constants.py` regenerates the committed round
constants.

The Rust MiMC core, proof crates, harness and analysis are not done yet.

## Parameters

See `params/PARAMS.md` for the chosen fields, exponent `e = 5`, round counts
`r = 2^k` for `k = 0..15`, and security settings.
