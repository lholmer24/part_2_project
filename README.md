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
| `python/` | Python MiMC reference, constant generator and analysis |
| `results/` | Benchmark CSV and metadata output |
| `docs/` | Proposal and dissertation material |

## Requirements

- Rust 1.98.1, pinned in `rust-toolchain.toml` and installed with rustup
- Python 3.11 or newer

## Commands

```sh
cargo build
cargo test
cargo test -p mimc --features extended-tests   # full sweep and Rust/Python agreement, about 3 min in debug
cargo clippy --all-targets
cargo fmt --all -- --check
cargo run -p harness -- --system groth16 --rounds 8

cd python
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/python -m mimc --field bls12_381_fr --rounds 8 --x 42
```

`python3 python/generate_round_constants.py` regenerates the committed round constants.

## Harness output

The harness writes `results/benchmarks.csv` and `results/benchmarks.meta.json`.
For each system it runs one untimed universal preparation, then, for each round
count: an untimed loading and reference-hash step, `--setup-samples` timed
setups if the system has a setup phase, `--warmup` untimed prove/verify pairs,
and `--samples` timed prove/verify pairs.

```
system,field,rounds,phase,sample,time_ns,proof_size_bytes
```

- `phase` is `setup`, `prove` or `verify`.
- `sample` is the repetition index within that phase. For `prove` and `verify`
  it is also the proof-instance index and selects the preimage.
- `time_ns` is the measured time in nanoseconds.
- `proof_size_bytes` is present on `prove` rows only.
