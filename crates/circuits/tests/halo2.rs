//! Halo2 acceptance and rejection tests.

use circuits::halo2::{domain_rows, instance_values, k_for_rows, params_k, MimcPreimageCircuit};
use halo2_proofs::{
    dev::MockProver,
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, ProvingKey,
        SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use mimc::{MimcParams, Statement, MAX_ROUNDS};
use rand_core_v10::UnwrapErr;
use rand_v10::rngs::SysRng;

const PREIMAGE: u64 = 12345;

fn statement(rounds: usize) -> (MimcParams<Fp>, Fp) {
    let params = MimcParams::<Fp>::load(rounds, 5).expect("load MiMC params");
    let hash = mimc::hash(&params, Fp::from(PREIMAGE));
    (params, hash)
}

/// `preimage` is `None` during key generation.
fn circuit(params: &MimcParams<Fp>, hash: Fp, preimage: Option<Fp>) -> MimcPreimageCircuit {
    MimcPreimageCircuit {
        statement: Statement {
            params: params.clone(),
            hash,
            preimage,
        },
    }
}

fn universal_parameters(rounds: usize) -> Params<EqAffine> {
    let (params, _hash) = statement(rounds);
    let k = params_k(&params).expect("measure circuit");
    Params::new(k)
}

struct Proof {
    vk: VerifyingKey<EqAffine>,
    hash: Fp,
    rounds: usize,
    bytes: Vec<u8>,
}

fn build_with(params: &Params<EqAffine>, rounds: usize) -> Proof {
    let (mimc, hash) = statement(rounds);

    let shape = circuit(&mimc, hash, None);
    let vk = keygen_vk(params, &shape).expect("keygen_vk");
    let pk: ProvingKey<EqAffine> = keygen_pk(params, vk.clone(), &shape).expect("keygen_pk");

    let instance = instance_values(hash, rounds);
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
        rounds,
        bytes: transcript.finalize(),
    }
}

fn build(rounds: usize) -> (Params<EqAffine>, Proof) {
    let params = universal_parameters(rounds);
    let proof = build_with(&params, rounds);
    (params, proof)
}

fn verify_with_hash(params: &Params<EqAffine>, proof: &Proof, hash: Fp) -> bool {
    let instance = instance_values(hash, proof.rounds);
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
    // Cheapest satisfiability check, with no key generation.
    for rounds in [1usize, 2, 4, 8] {
        let (params, hash) = statement(rounds);
        let k = params_k(&params).expect("measure circuit");

        let prover = MockProver::run(
            k,
            &circuit(&params, hash, Some(Fp::from(PREIMAGE))),
            vec![instance_values(hash, rounds)],
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

    // A flipped byte is either an invalid encoding or a failing evaluation.
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

#[test]
fn constraint_system_degree_matches_layout() {
    // A selector adds one degree, so each round gate is degree 3. Anything
    // larger multiplies the quotient domain by a power of two.
    let mut cs = ConstraintSystem::<Fp>::default();
    let _ = <MimcPreimageCircuit as Circuit<Fp>>::configure(&mut cs);

    assert_eq!(cs.degree(), 3);
}
