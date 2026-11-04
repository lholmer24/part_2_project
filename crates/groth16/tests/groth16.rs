//! Groth16 tests.
//!

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Proof;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;

use groth16::{prove, setup, verify, MimcParams, MimcPreimageCircuit};

const PREIMAGE: u64 = 12345;

fn statement(rounds: usize) -> (MimcParams<Fr>, Fr) {
    let params = MimcParams::<Fr>::load(rounds, 5).expect("load MiMC params");
    let hash = mimc::hash(&params, Fr::from(PREIMAGE));
    (params, hash)
}

fn circuit(params: MimcParams<Fr>, hash: Fr) -> MimcPreimageCircuit {
    MimcPreimageCircuit {
        params,
        hash,
        preimage: Some(Fr::from(PREIMAGE)),
    }
}

#[test]
fn valid_proof_at_every_round_count() {
    let mut rng = test_rng();
    for k in 0..=15 {
        let rounds = 1usize << k;
        let (params, hash) = statement(rounds);
        let setup = setup(params.clone(), &mut rng).expect("setup");
        let proof = prove(&setup, circuit(params, hash), &mut rng).expect("prove");
        assert!(verify(&setup, hash, &proof).expect("verify"));
    }
}

#[test]
fn wrong_public_hash_is_rejected() {
    let mut rng = test_rng();
    let (params, hash) = statement(8);
    let setup = setup(params.clone(), &mut rng).expect("setup");
    let proof = prove(&setup, circuit(params, hash), &mut rng).expect("prove");
    let wrong_hash = hash + Fr::from(1u64);

    assert!(!verify(&setup, wrong_hash, &proof).expect("verify"));
}

#[test]
fn altered_proof_is_rejected() {
    let mut rng = test_rng();
    let (params, hash) = statement(8);
    let setup = setup(params.clone(), &mut rng).expect("setup");
    let proof = prove(&setup, circuit(params, hash), &mut rng).expect("prove");

    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes).expect("serialise");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;

    if let Ok(altered) = Proof::<Bls12_381>::deserialize_compressed(&bytes[..]) {
        assert!(!verify(&setup, hash, &altered).expect("verify"));
    }
}

#[test]
fn constraint_count_matches_round_structure() {
    for k in 0..=15 {
        let rounds = 1usize << k;
        let (params, hash) = statement(rounds);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit(params, hash)
            .generate_constraints(cs.clone())
            .expect("synthesise");

        assert_eq!(cs.num_constraints(), 3 * rounds + 1);
    }
}
