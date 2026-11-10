//! PLONK acceptance and rejection tests.
//!
//! These tests exercise the circuit and the `dusk-plonk` API directly. The
//! harness adapter is tested through the `System` trait in
//! `crates/harness/tests`.

use circuits::plonk::{circuit_size, gate_count, MimcPreimageCircuit};
use dusk_bytes::Serializable;
use dusk_plonk::prelude::*;
use mimc::{MimcParams, Statement, MAX_ROUNDS};
use rand_core::OsRng;

/// Preimage used for every test statement.
const PREIMAGE: u64 = 12345;

/// Domain-separation label for the test circuit.
const LABEL: &[u8] = b"mimc-plonk-test";

/// The parameters and public hash for one round count.
fn statement(rounds: usize) -> (MimcParams<BlsScalar>, BlsScalar) {
    let params = MimcParams::<BlsScalar>::load(rounds, 5).expect("load MiMC params");
    let hash = mimc::hash(&params, BlsScalar::from(PREIMAGE));
    (params, hash)
}

/// Build one circuit value. `preimage` is `None` during setup.
fn circuit(
    params: MimcParams<BlsScalar>,
    hash: BlsScalar,
    preimage: Option<BlsScalar>,
) -> MimcPreimageCircuit {
    MimcPreimageCircuit {
        statement: Statement {
            params,
            hash,
            preimage,
        },
    }
}

/// Universal parameters large enough for `rounds` MiMC rounds.
fn universal_parameters(rounds: usize) -> PublicParameters {
    PublicParameters::setup(gate_count(rounds).next_power_of_two(), &mut OsRng)
        .expect("build public parameters")
}

/// Compile `rounds`, prove the statement, and return everything the verifier
/// needs.
///
/// The tuple is `(verifier, hash, proof, public_inputs)`.
fn build(rounds: usize) -> (Verifier, BlsScalar, Proof, Vec<BlsScalar>) {
    let public_parameters = universal_parameters(rounds);
    let (params, hash) = statement(rounds);
    let preimage = BlsScalar::from(PREIMAGE);

    let (prover, verifier) = Compiler::compile_with_circuit(
        &public_parameters,
        LABEL,
        &circuit(params.clone(), hash, None),
    )
    .expect("compile");

    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &circuit(params, hash, Some(preimage)))
        .expect("prove");

    (verifier, hash, proof, public_inputs)
}

#[test]
fn accepts_valid_proof() {
    for rounds in [1usize, 2, 4, 8, 16] {
        let (verifier, hash, proof, public_inputs) = build(rounds);
        assert_eq!(public_inputs, vec![hash]);
        assert!(verifier.verify(&proof, &public_inputs).is_ok());
    }
}

#[test]
fn rejects_proof_for_wrong_public_hash() {
    let (verifier, hash, proof, mut public_inputs) = build(8);
    public_inputs[0] = hash + BlsScalar::from(1u64);

    assert!(verifier.verify(&proof, &public_inputs).is_err());
}

#[test]
fn rejects_tampered_proof() {
    let (verifier, _hash, proof, public_inputs) = build(8);
    let mut bytes = proof.to_bytes();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;

    if let Ok(altered) = Proof::from_bytes(&bytes) {
        assert!(verifier.verify(&altered, &public_inputs).is_err());
    }
}

#[test]
fn gate_count_matches_round_structure() {
    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let (params, hash) = statement(rounds);

        assert_eq!(
            circuit_size(&params).expect("measure gate count"),
            gate_count(rounds)
        );

        let mut composer = Composer::initialized();
        circuit(params, hash, Some(BlsScalar::from(PREIMAGE)))
            .circuit(&mut composer)
            .expect("synthesise");

        assert_eq!(composer.constraints(), gate_count(rounds));
    }
}
