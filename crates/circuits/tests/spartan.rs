//! Spartan acceptance and rejection tests.
//!
//! These tests exercise the circuit and the `spartan` SNARK API directly. The
//! harness adapter is tested through the `System` trait in
//! `crates/harness/tests`.
//!
//! The full 16-count proof sweep is gated behind the `extended-tests` feature
//! because the largest instance dominates the runtime.

use circuits::spartan::{build_assignments, build_inputs, build_shape, MimcPreimageCircuit};
use curve25519_dalek_v4::scalar::Scalar;
use merlin_v3::Transcript;
use mimc::{MimcParams, Statement, MAX_ROUNDS};
use spartan_lib::{ComputationCommitment, SNARKGens, SNARK};

/// Preimage used for every test statement.
const PREIMAGE: u64 = 12345;

/// Domain-separation label for the test transcript.
const DOMAIN: &[u8] = b"mimc-spartan-test";

/// Independent expected constraint count for `rounds` MiMC rounds.
///
/// Hand-written counts belong in the tests, not in the circuit module. Three
/// multiplication constraints per round plus the final equality.
fn expected_constraint_count(rounds: usize) -> usize {
    3 * rounds + 1
}

/// Independent expected witness-variable count for `rounds` MiMC rounds.
///
/// The preimage plus three variables per round.
fn expected_variable_count(rounds: usize) -> usize {
    1 + 3 * rounds
}

/// The parameters and public hash for one round count.
fn statement(rounds: usize) -> (MimcParams<Scalar>, Scalar) {
    let params = MimcParams::<Scalar>::load(rounds, 5).expect("load MiMC params");
    let hash = mimc::hash(&params, Scalar::from(PREIMAGE));
    (params, hash)
}

/// Build one circuit value. `preimage` is `None` only when the witness is
/// deliberately absent.
fn circuit(
    params: &MimcParams<Scalar>,
    hash: Scalar,
    preimage: Option<Scalar>,
) -> MimcPreimageCircuit {
    MimcPreimageCircuit {
        statement: Statement {
            params: params.clone(),
            hash,
            preimage,
        },
    }
}

/// Generators sized from a measured synthesis of the circuit for `params`.
fn generators(params: &MimcParams<Scalar>) -> SNARKGens {
    let shape = build_shape(params).expect("measure circuit shape");
    SNARKGens::new(
        shape.padded_num_cons(),
        shape.num_vars,
        shape.num_inputs,
        shape.max_nonzeros(),
    )
}

/// Open a prover transcript bound to the round count.
fn prover_transcript(rounds: usize) -> Transcript {
    let mut transcript = Transcript::new(DOMAIN);
    transcript.append_u64(b"rounds", rounds as u64);
    transcript
}

/// Open a verifier transcript bound to the round count.
fn verifier_transcript(rounds: usize) -> Transcript {
    prover_transcript(rounds)
}

/// A proof and the statement data the verifier needs.
struct Proof {
    params: MimcParams<Scalar>,
    hash: Scalar,
    commitment: ComputationCommitment,
    proof: SNARK,
}

/// Prove the statement with caller-supplied generators.
fn build_with(gens: &SNARKGens, params: MimcParams<Scalar>, hash: Scalar) -> Proof {
    let rounds = params.rounds;

    let shape = build_shape(&params).expect("build R1CS shape");
    let instance = shape.instance().expect("build R1CS instance");
    let (commitment, decommitment) = SNARK::encode(&instance, gens);

    let assignments =
        build_assignments(&params, hash, Scalar::from(PREIMAGE)).expect("build assignments");
    let mut transcript = prover_transcript(rounds);
    let proof = SNARK::prove(
        &instance,
        &commitment,
        &decommitment,
        assignments.vars,
        &assignments.inputs,
        gens,
        &mut transcript,
    );

    Proof {
        params,
        hash,
        commitment,
        proof,
    }
}

/// Prove the statement for `rounds` with generators sized from the circuit.
fn build(rounds: usize) -> (SNARKGens, Proof) {
    let (params, hash) = statement(rounds);
    let gens = generators(&params);
    let proof = build_with(&gens, params, hash);
    (gens, proof)
}

/// Verify `proof` against `hash`.
fn verify_with_hash(gens: &SNARKGens, proof: &Proof, hash: Scalar) -> bool {
    let inputs = build_inputs(hash).expect("build public inputs");
    let mut transcript = verifier_transcript(proof.params.rounds);
    proof
        .proof
        .verify(&proof.commitment, &inputs, &mut transcript, gens)
        .is_ok()
}

#[test]
fn accepts_valid_proof() {
    for rounds in [1usize, 2, 4, 8] {
        let (gens, proof) = build(rounds);
        let hash = proof.hash;
        assert!(verify_with_hash(&gens, &proof, hash), "rounds = {rounds}");
    }
}

#[test]
#[cfg_attr(
    not(feature = "extended-tests"),
    ignore = "extended: run with --features extended-tests"
)]
fn accepts_valid_proof_at_every_round_count() {
    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let (params, hash) = statement(rounds);
        // Spartan generators are tied to one instance shape, so build a set
        // for each round count.
        let gens = generators(&params);
        let proof = build_with(&gens, params, hash);
        let hash = proof.hash;

        assert!(verify_with_hash(&gens, &proof, hash), "rounds = {rounds}");
    }
}

#[test]
fn rejects_proof_for_wrong_public_hash() {
    let (gens, proof) = build(8);
    let wrong_hash = proof.hash + Scalar::from(1u64);

    assert!(!verify_with_hash(&gens, &proof, wrong_hash));
}

#[test]
fn rejects_tampered_proof() {
    let (gens, proof) = build(8);
    let hash = proof.hash;

    let mut bytes = bincode::serialize(&proof.proof).expect("serialise proof");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;

    let accepted = match bincode::deserialize(&bytes) {
        Ok(tampered) => {
            let tampered = Proof {
                proof: tampered,
                ..proof
            };
            // Spartan 0.9 asserts inside verification for some malformed
            // proofs instead of returning an error. A panic is a rejection.
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                verify_with_hash(&gens, &tampered, hash)
            }))
            .unwrap_or(false)
        }
        // A byte flip that breaks the encoding is also a rejection.
        Err(_) => false,
    };

    assert!(!accepted);
}

#[test]
fn build_shape_reports_its_own_sizes() {
    for rounds in [1usize, 2, 8] {
        let params = MimcParams::<Scalar>::load(rounds, 5).expect("load MiMC params");
        let shape = build_shape(&params).expect("build R1CS shape");

        assert_eq!(shape.num_cons, expected_constraint_count(rounds));
        assert_eq!(shape.num_vars, expected_variable_count(rounds));
        assert_eq!(shape.num_inputs, 1);

        // Every entry must address the unpadded instance.
        let num_columns = shape.num_vars + 1 + shape.num_inputs;
        for matrix in [&shape.a, &shape.b, &shape.c] {
            for &(row, column, _) in matrix {
                assert!(row < shape.num_cons, "row {row} out of range");
                assert!(column < num_columns, "column {column} out of range");
            }
        }
    }
}

#[test]
fn shape_builds_an_instance() {
    for rounds in [1usize, 2, 8] {
        let params = MimcParams::<Scalar>::load(rounds, 5).expect("load MiMC params");
        let shape = build_shape(&params).expect("build R1CS shape");

        assert!(shape.instance().is_ok(), "rounds = {rounds}");
    }
}

#[test]
fn assignments_satisfy_the_instance() {
    for rounds in [1usize, 2, 8] {
        let (params, hash) = statement(rounds);
        let shape = build_shape(&params).expect("build R1CS shape");
        let instance = shape.instance().expect("build R1CS instance");

        let assignments =
            build_assignments(&params, hash, Scalar::from(PREIMAGE)).expect("build assignments");

        assert!(
            instance
                .is_sat(&assignments.vars, &assignments.inputs)
                .expect("check satisfiability"),
            "rounds = {rounds}"
        );
    }
}

#[test]
fn constraint_count_matches_round_structure() {
    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let (params, hash) = statement(rounds);

        let shape = build_shape(&params).expect("measure circuit shape");
        assert_eq!(shape.num_cons, expected_constraint_count(rounds));
        assert_eq!(shape.num_vars, expected_variable_count(rounds));
        assert_eq!(shape.num_inputs, 1);

        // The assignments must satisfy the instance that the builder emits.
        let instance = shape.instance().expect("build R1CS instance");
        let assignments =
            build_assignments(&params, hash, Scalar::from(PREIMAGE)).expect("build assignments");
        assert!(
            instance
                .is_sat(&assignments.vars, &assignments.inputs)
                .expect("check satisfiability"),
            "rounds = {rounds}"
        );
    }
}

#[test]
fn build_instance_returns_satisfying_assignment() {
    for rounds in [1usize, 4, 8] {
        let (params, hash) = statement(rounds);
        let circuit = circuit(&params, hash, Some(Scalar::from(PREIMAGE)));
        let built = circuits::spartan::build_instance(&circuit).expect("build instance");

        assert!(
            built
                .instance
                .is_sat(&built.vars, &built.inputs)
                .expect("check satisfiability"),
            "rounds = {rounds}"
        );
    }
}
