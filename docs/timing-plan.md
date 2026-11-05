# Timing boundaries

This document fixes what the benchmark times and what it excludes. The goal is
to compare implementations of the proof systems, so all work needed to produce,
prove and verify a statement is measured, including our circuit synthesis and
witness construction.

## Principles

1. Time the work needed to run each system, including circuit synthesis,
   constraint construction, witness generation and trace generation.
2. Exclude only I/O, reference hashing, universal parameter generation, proof
   serialisation and proof deserialisation.
3. Time setup, proving and verification with separate timers.
4. Generate universal, reusable parameters once at the largest size, outside
   the per-configuration sweep. Report them separately, not as per-round setup.
5. Run every measurement single-threaded.

## Timing site

The harness starts and stops every timer in `run_systems`. It times three calls:

1. `System::setup`
2. `System::prove`
3. `System::verify`

Adapters contain no timers. `System::prepare_universal`,
`System::prepare` and `System::proof_size` are untimed. This keeps the measured
boundary identical for every system. `System::prove` returns an opaque
`ProofBox`; the harness passes it to `proof_size` and `verify`.

`System::prepare_universal(max_rounds)` runs once per system before the round
loop. `System::prepare(rounds)` runs once per configuration. Universal
parameters must be stored outside the per-configuration state.

## Common phases

| Phase | Timed | Untimed |
|:---|:---|:---|
| Universal prepare | Nothing | Reusable parameters at the largest size |
| Prepare | Nothing | Round constants, reference hash |
| Setup | Adapter call: circuit construction plus library setup | File I/O, universal parameters |
| Prove | Adapter call: circuit, witness or trace construction plus library prover | Proof serialisation and size measurement |
| Verify | Adapter call: library verifier | Proof deserialisation |
| Proof size | Nothing | Serialisation after the prove timer stops |

The reference hash is a statement input, not a proof-system operation. It is
computed once in prepare. Circuit synthesis is part of the measured work.

## Universal parameters

| System | Universal artefact | Handling |
|:---|:---|:---|
| Groth16 | None | Circuit-specific trusted setup |
| PLONK | KZG public parameters | Build once at maximum degree; exclude from per-round setup |
| Bulletproofs | Pedersen and Bulletproof generators | Build once at maximum size; exclude from per-round setup |
| STARK | None | No setup |
| Halo2 | IPA `Params` | Build once at maximum `k`; exclude from per-round setup |
| Spartan | `SNARKGens` | Build once at maximum size; exclude from per-round setup |

The one-time universal cost is reported in the text, not in the per-round CSV.
It is generated in `System::prepare_universal` before the round loop.

## Groth16

Library: `ark-groth16` 0.6 over BLS12-381.

| Segment | Boundary |
|:---|:---|
| Untimed prepare | `MimcParams::load`, `mimc::hash` |
| Timed setup | `Groth16::generate_random_parameters_with_reduction`: circuit synthesis plus key generation |
| Timed prove | `Groth16::create_random_proof_with_reduction`: circuit synthesis, witness construction and proof generation |
| Timed verify | `Groth16::verify_proof` |
| Untimed | Proof serialisation and size measurement |

Setup and proving each run the circuit. In setup mode arkworks builds the
constraint shape without evaluating the input or witness closures. In proving
mode it builds the same shape and evaluates the witness. Setup runs once per
circuit and is amortised; proving runs for every proof.

`crates/circuits/src/groth16.rs` defines only `MimcPreimageCircuit`. The adapter in
`crates/harness/src/systems/groth16.rs` calls arkworks directly.

## PLONK

Library: `dusk-plonk` 0.24 over BLS12-381.

| Segment | Boundary |
|:---|:---|
| Untimed prepare | `MimcParams::load`, `mimc::hash` |
| Universal, once | `PublicParameters::setup(max_degree)` |
| Timed setup | `Compiler::compile_with_circuit`: circuit synthesis plus compilation |
| Timed prove | `Prover::prove`: circuit synthesis plus proof generation |
| Timed verify | `Verifier::verify` |
| Untimed | Proof serialisation and size measurement |

`circuits::plonk::MimcPreimageCircuit` implements `dusk_plonk::Circuit`. The adapter is
`crates/harness/src/systems/plonk.rs`.

## Bulletproofs

Library: pinned `bulletproofs` develop revision, R1CS API.

| Segment | Boundary |
|:---|:---|
| Untimed prepare | `MimcParams::load`, `mimc::hash` |
| Universal, once | `PedersenGens` and `BulletproofGens::new` at maximum size |
| Timed setup | None; Bulletproofs is transparent |
| Timed prove | Constraint construction, witness commitments, and `Prover::prove` |
| Timed verify | `R1CSProof::verify` |
| Untimed | Proof serialisation and size measurement |

The prover block starts before the constraint list is built and ends after
`Prover::prove` returns. This includes our constraint construction by design.
`circuits::bulletproofs::constrain_prover` and
`circuits::bulletproofs::constrain_verifier` add the
statement to the prover and verifier R1CS. The adapter creates both and calls
them inside the timed block.

## STARK

Library: `winterfell` 0.13 over `f128`.

| Segment | Boundary |
|:---|:---|
| Untimed prepare | `MimcParams::load`, `mimc::hash`, proof options |
| Timed setup | None; STARK is transparent |
| Timed prove | AIR construction, trace generation, `Prover::prove(trace)` |
| Timed verify | `verify(proof, public_inputs)` |
| Untimed | Proof serialisation and size measurement |

The AIR is circuit synthesis, so it is timed with the prover. Trace generation
is part of proving and is also timed. `circuits::stark::build_trace` builds the trace; the
adapter calls the AIR, the trace builder and the winterfell prover inside the
timed block.

## Halo2

Library: `halo2_proofs` 0.4.1 over Pasta.

| Segment | Boundary |
|:---|:---|
| Untimed prepare | `MimcParams::load`, `mimc::hash` |
| Universal, once | `Params::new(k_max)` |
| Timed setup | `keygen_vk` plus `keygen_pk`: circuit synthesis and key generation |
| Timed prove | `create_proof`: circuit synthesis, witness assignment and proof generation |
| Timed verify | `verify_proof` |
| Untimed | Proof serialisation and size measurement |

`circuits::halo2::MimcPreimageCircuit` implements `halo2_proofs::plonk::Circuit`. The
adapter is `crates/harness/src/systems/halo2.rs`.

## Spartan

Library: `spartan` 0.9 over Ristretto255.

| Segment | Boundary |
|:---|:---|
| Untimed prepare | `MimcParams::load`, `mimc::hash` |
| Universal, once | `SNARKGens::new` at maximum size |
| Timed setup | R1CS matrix construction plus `SNARK::encode` |
| Timed prove | Witness assignment construction plus `SNARK::prove` |
| Timed verify | `SNARK::verify` |
| Untimed | Proof serialisation and size measurement |

Spartan has no trusted setup. The timed setup row is the deterministic
preprocessing: building the matrices and committing to the instance.
`circuits::spartan::build_instance` builds the R1CS instance and assignments; the adapter
calls `SNARK::encode` and `SNARK::prove` directly.

## CSV meaning

`phase=setup` means the timed per-circuit setup above. It includes circuit or
instance synthesis, but not file loading, reference hashing or universal
parameters.

Systems with no per-circuit setup produce no `setup` rows:

- Bulletproofs
- STARK

`proof_size_bytes` is recorded from the serialised proof after the prove timer
stops.

## Consistency

Every system includes its own circuit, constraint, witness or trace synthesis in
the timed phases. Systems whose libraries synthesise the circuit internally
include that work automatically. Systems with explicit construction time the
construction block.

The phases therefore measure:

- the project's circuit encoding,
- the library's setup, prover and verifier,
- the data transformation needed to call them.

They exclude:

- file I/O,
- the reference MiMC hash,
- universal parameters,
- serialisation and deserialisation.

## Circuit layout

One crate, `crates/circuits`, holds the circuit, AIR or constraint layout for
every system. Each system is one module and one file. The crate holds no setup,
prove or verify wrapper. The harness adapter calls the proof-system library
directly, so each timed call is visible in one adapter method.

Bulletproofs, STARK and Spartan keep their constraint, trace or matrix builder
next to the circuit. The initial builder bodies are `todo!()`. Adapters for
unimplemented systems are declared in `crates/harness/src/systems/` but are not
registered in `harness::systems()`.

A new system follows the same pattern:

1. Add `crates/circuits/src/<system>.rs` and declare it in `lib.rs`.
2. Add the builder for constraints, trace or matrices in the same file.
3. Add an adapter in `crates/harness/src/systems/<system>.rs`.
4. Implement `System`, with no timers in the adapter.
5. Register the adapter in `harness::systems`.
