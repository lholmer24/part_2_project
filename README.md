# Who Knows? A Comparison of Zero-Knowledge Proof Systems

Part II project benchmarking Groth16, PLONK, Bulletproofs, STARK, Halo2 and
Spartan on a MiMC preimage statement.

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
cargo test -p mimc --features extended-tests   # full sweep + Rust/Python agreement
cargo clippy --all-targets
cargo fmt --all -- --check
cargo test -p circuits
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

The harness registers the placeholder and Groth16 adapters. PLONK, Bulletproofs,
STARK, Halo2 and Spartan have circuit skeletons in `crates/circuits` and adapter
skeletons in `crates/harness/src/systems`, but the bodies are not implemented
yet, so they are not registered. The analysis is not done yet. The harness writes
`results/benchmarks.csv` and `results/benchmarks.meta.json`.

## Harness output

Setup, proving and verification are timed separately. The harness owns every
timer. For each system it runs one untimed universal preparation, then for each
round count it runs:

1. An untimed preparation step: constants and reference hash.
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

Universal parameters that are reused across configurations are generated once
before the round sweep and reported separately. The CSV records only measured
data; the report explains the setup type and phase boundaries for each system.

Phase boundaries for Groth16:

- Preparation, untimed: load the round constants and compute the reference hash.
- Setup, timed: circuit synthesis plus key generation.
- Prove, timed: circuit synthesis, witness construction and proof generation.
- Verify, timed: verification only. Proof serialisation is outside the timer.

The harness starts and stops all three timers. The adapter in
`crates/harness/src/systems/groth16.rs` calls `ark-groth16` directly, and
`crates/circuits/src/groth16.rs` holds only the circuit.

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
