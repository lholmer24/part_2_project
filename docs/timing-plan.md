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
| Prepare | Nothing | Round constants and reference hash for the default instance |
| Prepare instance | Nothing | Preimage and reference hash for one proof sample |
| Setup | Adapter call: circuit construction plus library setup | File I/O, universal parameters |
| Prove | Adapter call: circuit, witness or trace construction plus library prover | Proof serialisation and size measurement |
| Verify | Adapter call: library verifier | Proof deserialisation |
| Proof size | Nothing | Serialisation after the prove timer stops |

The reference hash is a statement input, not a proof-system operation. It is
computed once in `prepare` and again in each untimed `prepare_instance`.
Circuit synthesis is part of the measured work. `prepare_instance` runs before
every warm-up and timed proof, so each `prove`/`verify` sample uses its own
uniform native-field preimage and does not repeat a fixed statement.

Bulletproofs and STARK have no per-system setup, so they write no `setup` rows.
`proof_size_bytes` comes from the serialised proof after the prove timer stops.

## Universal parameters

Groth16's setup is circuit-specific, and STARK has no setup. The other systems
build reusable parameters in `System::prepare_universal` before the round loop.
Their one-time cost is reported in the text, not in the per-round CSV.

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

## Bulletproofs

Library: pinned `bulletproofs` develop revision, R1CS API.

| Segment | Boundary |
|:---|:---|
| Untimed prepare | `MimcParams::load`, `mimc::hash` |
| Universal, once | `PedersenGens` and `BulletproofGens::new` at maximum size |
| Timed setup | None; Bulletproofs is transparent |
| Timed prove | Constraint construction, witness commitments, and `Prover::prove` |
| Timed verify | `Verifier::verify` |
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

Winterfell builds the AIR itself inside `prove` and `verify`, so the round
constants travel with `MimcPublicInputs` instead of being reloaded by
`Air::new`. The constants are protocol parameters, not public inputs, so
`ToElements` hashes only the hash and the round count. This keeps the file read
and decimal parse out of the timed phases.

## Halo2

Library: `halo2_proofs` 0.4.1 over Pasta.

| Segment | Boundary |
|:---|:---|
| Untimed prepare | `MimcParams::load`, `mimc::hash` |
| Universal, once | `Params::new(k)` for every measured `k` in `1..=k_max` |
| Timed setup | `keygen_vk` plus `keygen_pk`: circuit synthesis and key generation |
| Timed prove | `create_proof`: circuit synthesis, witness assignment and proof generation |
| Timed verify | `verify_proof` |
| Untimed | Proof serialisation and size measurement |

`circuits::halo2::params_k` synthesises the circuit with `MockProver` and
returns the smallest domain exponent `k` that holds it. `prepare_universal`
builds one `Params` per `k` up to the largest configuration and caches them;
`prepare` measures `k` for the current round count and selects that set. The
measurement belongs to parameter selection, so it is untimed like the parameter
generation itself. Timed setup, prove and verify then scale with the domain the
circuit needs, which is the same boundary as PLONK's per-circuit KZG trim. IPA
parameters cannot be trimmed, because `Params::new(k)` derives the generator and
Lagrange bases for that exact `k`, so one set per `k` is the equivalent.

Halo2 timings remain a staircase in the domain `2^k`, not a function of the
round count, because consecutive round counts can share a domain.

The finish gate reads the public hash from the instance column on row `rounds`,
so the instance vector has length `rounds + 1`. Building it from the reference
hash belongs to statement preparation, like the hash itself: the adapter builds
it in `prepare` and `prepare_instance`, outside the timed phases.

## Spartan

Library: `spartan` 0.9 over Ristretto255.

| Segment | Boundary |
|:---|:---|
| Untimed prepare | `MimcParams::load`, `mimc::hash` |
| Universal, once | One `SNARKGens` per measured shape |
| Timed setup | R1CS matrix construction plus `SNARK::encode` |
| Timed prove | Witness assignment construction plus `SNARK::prove` |
| Timed verify | `SNARK::verify` |
| Untimed | Proof serialisation and size measurement |

Spartan has no trusted setup. The timed setup row is the deterministic
preprocessing: building the matrices and committing to the instance.
`circuits::spartan::build_shape` builds the R1CS matrices; the adapter turns
them into an `Instance` and calls `SNARK::encode`. Proving builds the witness
and input assignments with `circuits::spartan::build_assignments` and calls
`SNARK::prove`.

`SNARKGens::new` pads `num_vars` itself but not `num_cons`. It passes
`num_cons` to `R1CSCommitmentGens`, which calls `num_cons.log_2()`, while
`Instance::new` pads `num_cons` to a power of two. `prepare_universal` must
therefore pass `R1CSShape::padded_num_cons()` and the measured
`R1CSShape::max_nonzeros()`.

Spartan also fixes the generator lengths to one instance shape:
`MultiCommitGens::commit` asserts `gens_n.n == scalars.len()`, so a max-size
set cannot serve a smaller instance. `prepare_universal` builds the set for the
largest round count, and `prepare` caches the set for each smaller round count
it sees. Building a set is untimed, like universal parameter generation for the
other systems.
