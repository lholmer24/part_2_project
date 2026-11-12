//! Groth16 circuit tests.
//!
//! These tests exercise the circuit and the arkworks API directly. The harness
//! adapter is tested through the `System` trait in `crates/harness/tests`.

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;
use circuits::groth16::MimcPreimageCircuit;
use mimc::{MimcParams, Statement, MAX_ROUNDS};

const PREIMAGE: u64 = 12345;

fn statement(rounds: usize) -> (MimcParams<Fr>, Fr) {
    let params = MimcParams::<Fr>::load(rounds, 5).expect("load MiMC params");
    let hash = mimc::hash(&params, Fr::from(PREIMAGE));
    (params, hash)
}

fn circuit(params: MimcParams<Fr>, hash: Fr) -> MimcPreimageCircuit {
    MimcPreimageCircuit {
        statement: Statement {
            params,
            hash,
            preimage: Some(Fr::from(PREIMAGE)),
        },
    }
}

fn build(rounds: usize) -> (PreparedVerifyingKey<Bls12_381>, Fr, Proof<Bls12_381>) {
    let mut rng = test_rng();
    let (params, hash) = statement(rounds);

    let proving_key = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
        circuit(params.clone(), hash),
        &mut rng,
    )
    .expect("setup");
    let prepared_verifying_key = prepare_verifying_key(&proving_key.vk);
    let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
        circuit(params, hash),
        &proving_key,
        &mut rng,
    )
    .expect("prove");

    (prepared_verifying_key, hash, proof)
}

#[test]
fn valid_proof_at_selected_round_counts() {
    for rounds in [1usize, 2, 4, 8, 16] {
        let (prepared_verifying_key, hash, proof) = build(rounds);
        assert!(
            Groth16::<Bls12_381>::verify_proof(&prepared_verifying_key, &proof, &[hash])
                .expect("verify")
        );
    }
}

#[test]
#[cfg_attr(
    not(feature = "extended-tests"),
    ignore = "extended: run with --features extended-tests"
)]
fn valid_proof_at_every_round_count() {
    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let (prepared_verifying_key, hash, proof) = build(rounds);

        assert!(
            Groth16::<Bls12_381>::verify_proof(&prepared_verifying_key, &proof, &[hash])
                .expect("verify"),
            "rounds = {rounds}"
        );
    }
}

#[test]
fn wrong_public_hash_is_rejected() {
    let (prepared_verifying_key, hash, proof) = build(8);
    let wrong_hash = hash + Fr::from(1u64);

    assert!(
        !Groth16::<Bls12_381>::verify_proof(&prepared_verifying_key, &proof, &[wrong_hash])
            .expect("verify")
    );
}

#[test]
fn altered_proof_is_rejected() {
    let (prepared_verifying_key, hash, proof) = build(8);

    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes).expect("serialise");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;

    if let Ok(altered) = Proof::<Bls12_381>::deserialize_compressed(&bytes[..]) {
        assert!(
            !Groth16::<Bls12_381>::verify_proof(&prepared_verifying_key, &altered, &[hash])
                .expect("verify")
        );
    }
}

#[test]
fn constraint_count_matches_round_structure() {
    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let (params, hash) = statement(rounds);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit(params, hash)
            .generate_constraints(cs.clone())
            .expect("synthesise");

        assert_eq!(cs.num_constraints(), 3 * rounds + 1);
    }
}

#[test]
fn circuit_is_satisfied() {
    let (params, hash) = statement(8);
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit(params, hash)
        .generate_constraints(cs.clone())
        .expect("synthesise");

    assert!(cs.is_satisfied().expect("check satisfaction"));
}
