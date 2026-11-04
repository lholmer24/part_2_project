# Who Knows? A Comparison of Zero-Knowledge Proof Systems

Part II project benchmarking Groth16, PLONK, Bulletproofs, STARK, Halo2 and
Spartan on a MiMC preimage statement.

## Layout

| Path | Purpose |
|---|---|
| `crates/mimc/` | Shared MiMC core, constants loader and field adapters |
| `crates/harness/` | Common setup/prove/verify interface, phase CSV and metadata output |
| `crates/groth16/` | Groth16 over BLS12-381 |
| `crates/plonk/` | PLONK over BLS12-381 |
| `crates/bulletproofs/` | Bulletproofs over Ristretto255 |
| `crates/stark/` | STARK over winterfell `f128` |
| `crates/halo2/` | Halo2 over Pasta |
| `crates/spartan/` | Spartan over Ristretto255 |
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
cargo test -p mimc --features extended-tests   # full sweep + Rust/Python agreement
cargo clippy --all-targets
cargo fmt --all -- --check
cargo test -p groth16
cargo run -p harness -- --system placeholder --rounds 8

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

The harness runs with a placeholder and Groth16. PLONK, Bulletproofs, STARK,
Halo2, Spartan and the analysis are not done yet. The harness writes
`results/benchmarks.csv` and `results/benchmarks.meta.json`.

## Harness output

Setup, proving and verification are timed separately. For each system and round
count, the harness runs:

1. An untimed preparation step: constants, circuit and witness data.
2. `--setup-samples` timed setups, if the system has a setup phase.
3. `--warmup` untimed prove/verify pairs.
4. `--samples` timed prove/verify pairs.

The CSV has one row per timed phase repetition:

```
system,field,rounds,phase,sample,time_ns,proof_size_bytes
```

- `phase` is `setup`, `prove` or `verify`.
- `sample` is the repetition index within that phase.
- `time_ns` is the measured time in nanoseconds.
- `proof_size_bytes` is present on `prove` rows only.
- A system without a setup phase has no `setup` rows.

Universal parameters that are reused across configurations are generated
outside the sweep and reported separately. The CSV records only measured data;
the paper explains the setup type and phase boundaries for each system.

Phase boundaries for Groth16:

- Preparation, untimed: load the round constants and compute the reference hash.
- Setup, timed: circuit synthesis plus key generation.
- Prove, timed: circuit synthesis, witness construction and proof generation.
- Verify, timed: verification only. Proof deserialisation is outside the timer.

See `docs/timing-plan.md` for the exact timed and untimed segments of every
system. Circuit synthesis is counted as measured work throughout.

The harness also writes `<name>.meta.json` next to the CSV. It records the
timestamp, git commit, build profile, host, CPU, systems, round counts and
sample settings. The CSV stays numeric; the sidecar carries reproducibility
metadata.

The Rust harness only measures and writes raw data. The Python analysis reads
the CSV and metadata, prints summaries and renders figures. The analysis scripts
are not done yet.

## Parameters

See `params/PARAMS.md` for the chosen fields, exponent `e = 5`, round counts
`r = 2^k` for `k = 0..15`, and security settings.
