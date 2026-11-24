# Who Knows? A Comparison of Zero-Knowledge Proof Systems

Part II project benchmarking Groth16, PLONK, Bulletproofs, STARK, Halo2 and Spartan on a MiMC preimage statement.

## Layout

| Path | Purpose |
|---|---|
| `crates/mimc/` | Shared MiMC core, constants loader and field adapters |
| `crates/circuits/` | MiMC circuits for all six systems, one file per system |
| `crates/harness/` | Common `System` interface, one adapter per system, phase CSV and metadata output |
| `params/PARAMS.md` | Field, exponent, round-count and security parameters |
| `params/round_constants/` | Generated round constants, one file per field |
| `python/` | Python MiMC reference, constant generator, analysis and profiling |
| `results/` | Benchmark CSV, figures and interactive profiles |
| `docs/` | Proposal and dissertation material |

## Requirements

- Rust 1.98.1, pinned in `rust-toolchain.toml` and installed with rustup
- Python 3.11 or newer
- `perf` and `inferno` for the flame charts (optional)

## Commands

```sh
# Install/setup
rustup toolchain install 1.98.1 --component clippy --component rustfmt
python3 -m venv python/.venv
python/.venv/bin/pip install -e 'python[dev]'

# Build
cargo build --release

# Test
cargo test
python/.venv/bin/python -m pytest python/tests

# Test extended
cargo test --release -p mimc -p circuits --features mimc/extended-tests,circuits/extended-tests

# Regenerate round constants (optional)
python/.venv/bin/python python/generate_round_constants.py

# Generate full dataset
cargo run --release -p harness

# Plot full dataset
python/.venv/bin/python -m analysis results/benchmarks/benchmarks.csv

# Generate the profiling dataset and explorer: results/profiles/index.html
python/.venv/bin/python -m profiling
