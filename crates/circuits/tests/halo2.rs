//! Halo2 acceptance and rejection tests.
//!
//! These tests exercise the circuit and the `halo2_proofs` API directly. The
//! harness adapter is tested through the `System` trait in `crates/harness/tests`.
//!
//! The tests assume the instance layout of `circuits::halo2`: one instance
//! column that holds the public hash `h` in row 0.
//!
//! The full 16-count proof sweep is gated behind the `extended-tests` feature
//! because the largest key generation dominates the runtime.

use circuits::halo2::{domain_rows, k_for_rows, params_k, MimcPreimageCircuit};
use halo2_proofs::{
    dev::MockProver,
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use mimc::{MimcParams, Statement, MAX_ROUNDS};
use rand_core_v10::UnwrapErr;
use rand_v10::rngs::SysRng;

/// Preimage used for every test statement.
const PREIMAGE: u64 = 12345;

/// The parameters and public hash for one round count.
fn statement(rounds: usize) -> (MimcParams<Fp>, Fp) {
    let params = MimcParams::<Fp>::load(rounds, 5).expect("load MiMC params");
    let hash = mimc::hash(&params, Fp::from(PREIMAGE));
    (params, hash)
}

/// Build one circuit value. `preimage` is `None` during key generation.
fn circuit(params: &MimcParams<Fp>, hash: Fp, preimage: Option<Fp>) -> MimcPreimageCircuit {
    MimcPreimageCircuit {
        statement: Statement {
            params: params.clone(),
            hash,
            preimage,
        },
    }
}

/// Universal IPA parameters large enough for `rounds` MiMC rounds, sized from a
/// measured synthesis of the circuit.
fn universal_parameters(rounds: usize) -> Params<EqAffine> {
    let (params, _hash) = statement(rounds);
    let k = params_k(&params).expect("measure circuit");
    Params::new(k)
}

/// The values the verifier needs for one proof.
struct Proof {
    /// Verifying key for this configuration.
    vk: VerifyingKey<EqAffine>,
    /// Public hash the proof was built for.
    hash: Fp,
    /// Serialised proof, the wire format that `verify` reads back.
    bytes: Vec<u8>,
}

/// Generate keys for `rounds`, prove the statement, and return the verifier
/// inputs.
fn build_with(params: &Params<EqAffine>, rounds: usize) -> Proof {
    let (mimc, hash) = statement(rounds);

    let shape = circuit(&mimc, hash, None);
    let vk = keygen_vk(params, &shape).expect("keygen_vk");
    let pk: ProvingKey<EqAffine> = keygen_pk(params, vk.clone(), &shape).expect("keygen_pk");

    let instance = [hash];
    let columns: [&[Fp]; 1] = [&instance];
    let instances: [&[&[Fp]]; 1] = [&columns];

    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    create_proof(
        params,
        &pk,
        &[circuit(&mimc, hash, Some(Fp::from(PREIMAGE)))],
        &instances,
        UnwrapErr(SysRng),
        &mut transcript,
    )
    .expect("prove");

    Proof {
        vk,
        hash,
        bytes: transcript.finalize(),
    }
}

/// Generate fresh parameters, keys and a proof for `rounds`.
fn build(rounds: usize) -> (Params<EqAffine>, Proof) {
    let params = universal_parameters(rounds);
    let proof = build_with(&params, rounds);
    (params, proof)
}

/// Verify `proof` against `hash`.
fn verify_with_hash(params: &Params<EqAffine>, proof: &Proof, hash: Fp) -> bool {
    let instance = [hash];
    let columns: [&[Fp]; 1] = [&instance];
    let instances: [&[&[Fp]]; 1] = [&columns];

    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&proof.bytes[..]);
    verify_proof(
        params,
        &proof.vk,
        SingleVerifier::new(params),
        &instances,
        &mut transcript,
    )
    .is_ok()
}

#[test]
fn mock_prover_accepts_valid_witness() {
    // The cheapest check while filling the circuit body: this catches a wrong
    // gate, a missing copy constraint or a wrong instance value without any key
    // generation.
    for rounds in [1usize, 2, 4, 8] {
        let (params, hash) = statement(rounds);
        let k = params_k(&params).expect("measure circuit");

        let prover = MockProver::run(
            k,
            &circuit(&params, hash, Some(Fp::from(PREIMAGE))),
            vec![vec![hash]],
        )
        .expect("run mock prover");

        prover.assert_satisfied();
    }
}

#[test]
fn accepts_valid_proof() {
    for rounds in [1usize, 2, 4, 8, 16] {
        let (params, proof) = build(rounds);
        let hash = proof.hash;

        assert!(verify_with_hash(&params, &proof, hash), "rounds = {rounds}");
    }
}

#[test]
#[cfg_attr(
    not(feature = "extended-tests"),
    ignore = "extended: run with --features extended-tests"
)]
fn accepts_valid_proof_at_every_round_count() {
    // One universal parameter set covers every round count, as in the harness.
    let params = universal_parameters(MAX_ROUNDS);

    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let proof = build_with(&params, rounds);
        let hash = proof.hash;

        assert!(verify_with_hash(&params, &proof, hash), "rounds = {rounds}");
    }
}

#[test]
fn rejects_proof_for_wrong_public_hash() {
    let (params, proof) = build(8);
    let wrong_hash = proof.hash + Fp::from(1u64);

    assert!(!verify_with_hash(&params, &proof, wrong_hash));
}

#[test]
fn rejects_tampered_proof() {
    let (params, proof) = build(8);

    // The proof is stored in its wire format, so a flipped byte is either an
    // invalid encoding or a failing evaluation. Both must be rejected.
    let mut bytes = proof.bytes.clone();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;

    let tampered = Proof { bytes, ..proof };
    let hash = tampered.hash;

    assert!(!verify_with_hash(&params, &tampered, hash));
}

#[test]
fn domain_matches_round_structure() {
    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let (params, _hash) = statement(rounds);

        assert_eq!(
            params_k(&params).expect("measure circuit"),
            k_for_rows(domain_rows(rounds)),
            "rounds = {rounds}"
        );
    }
}
