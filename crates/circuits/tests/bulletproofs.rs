//! Bulletproofs acceptance and rejection tests.

use bulletproofs_lib::r1cs::{ConstraintSystem, Prover, R1CSProof, Verifier};
use bulletproofs_lib::{BulletproofGens, PedersenGens};
use circuits::bulletproofs::{
    circuit_size, constrain_prover, constrain_verifier, constraint_count, generator_capacity,
    multiplier_count, public_hash_commitment, MimcCommitments, MimcPreimageCircuit,
};
use curve25519_dalek_v3::scalar::Scalar;
use merlin::Transcript;
use mimc::{MimcParams, Statement, MAX_ROUNDS};

const PREIMAGE: u64 = 12345;

/// Fixed blinding so the tests do not depend on an RNG.
const PREIMAGE_BLINDING: u64 = 0xB11D;

const DOMAIN: &[u8] = b"mimc-bulletproofs-test";

fn statement(rounds: usize) -> (MimcParams<Scalar>, Scalar) {
    let params = MimcParams::<Scalar>::load(rounds, 5).expect("load MiMC params");
    let hash = mimc::hash(&params, Scalar::from(PREIMAGE));
    (params, hash)
}

/// `preimage` is `None` only when the witness is deliberately absent.
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

fn generators(params: &MimcParams<Scalar>) -> (PedersenGens, BulletproofGens) {
    let size = circuit_size(params).expect("measure circuit size");
    (
        PedersenGens::default(),
        BulletproofGens::new(generator_capacity(size.multipliers), 1),
    )
}

fn prover_transcript(rounds: usize) -> Transcript {
    let mut transcript = Transcript::new(DOMAIN);
    transcript.append_u64(b"rounds", rounds as u64);
    transcript
}

fn verifier_transcript(rounds: usize) -> Transcript {
    prover_transcript(rounds)
}

struct Proof {
    params: MimcParams<Scalar>,
    hash: Scalar,
    proof: R1CSProof,
    commitments: MimcCommitments,
}

fn build_with(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    params: MimcParams<Scalar>,
    hash: Scalar,
) -> Proof {
    let rounds = params.rounds;

    let mut transcript = prover_transcript(rounds);
    let mut prover = Prover::new(pc_gens, &mut transcript);
    let commitments = constrain_prover(
        &mut prover,
        &circuit(&params, hash, Some(Scalar::from(PREIMAGE))),
        Scalar::from(PREIMAGE_BLINDING),
    )
    .expect("add prover constraints");
    let proof = prover.prove(bp_gens).expect("prove");

    Proof {
        params,
        hash,
        proof,
        commitments,
    }
}

fn build(rounds: usize) -> (PedersenGens, BulletproofGens, Proof) {
    let (params, hash) = statement(rounds);
    let (pc_gens, bp_gens) = generators(&params);
    let proof = build_with(&pc_gens, &bp_gens, params, hash);
    (pc_gens, bp_gens, proof)
}

fn verify_with_hash(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proof: &Proof,
    hash: Scalar,
) -> bool {
    let mut transcript = verifier_transcript(proof.params.rounds);
    let mut verifier = Verifier::new(&mut transcript);

    if constrain_verifier(
        pc_gens,
        &mut verifier,
        &proof.params,
        hash,
        &proof.commitments,
    )
    .is_err()
    {
        return false;
    }

    verifier.verify(&proof.proof, pc_gens, bp_gens).is_ok()
}

#[test]
fn accepts_valid_proof() {
    for rounds in [1usize, 2, 4, 8] {
        let (pc_gens, bp_gens, proof) = build(rounds);
        let hash = proof.hash;
        assert!(
            verify_with_hash(&pc_gens, &bp_gens, &proof, hash),
            "rounds = {rounds}"
        );
    }
}

#[test]
#[cfg_attr(
    not(feature = "extended-tests"),
    ignore = "extended: run with --features extended-tests"
)]
fn accepts_valid_proof_at_every_round_count() {
    let max_params = MimcParams::<Scalar>::load(MAX_ROUNDS, 5).expect("load MiMC params");
    let (pc_gens, bp_gens) = generators(&max_params);

    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let (params, hash) = statement(rounds);
        let proof = build_with(&pc_gens, &bp_gens, params, hash);
        let hash = proof.hash;

        assert!(
            verify_with_hash(&pc_gens, &bp_gens, &proof, hash),
            "rounds = {rounds}"
        );
    }
}

#[test]
fn rejects_proof_for_wrong_public_hash() {
    let (pc_gens, bp_gens, proof) = build(8);
    let wrong_hash = proof.hash + Scalar::one();

    assert!(!verify_with_hash(&pc_gens, &bp_gens, &proof, wrong_hash));
}

#[test]
fn rejects_tampered_proof() {
    let (pc_gens, bp_gens, proof) = build(8);

    let mut bytes = proof.proof.to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;

    let accepted = match R1CSProof::from_bytes(&bytes) {
        Ok(tampered) => {
            let tampered = Proof {
                proof: tampered,
                ..proof
            };
            let hash = tampered.hash;
            verify_with_hash(&pc_gens, &bp_gens, &tampered, hash)
        }
        // A byte flip that breaks the encoding is also a rejection.
        Err(_) => false,
    };

    assert!(!accepted);
}

#[test]
fn multiplier_and_constraint_count_match_round_structure() {
    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let (params, hash) = statement(rounds);
        let pc_gens = PedersenGens::default();

        let measured = circuit_size(&params).expect("measure circuit size");
        assert_eq!(measured.multipliers, multiplier_count(rounds));
        assert_eq!(measured.constraints, constraint_count(rounds));

        // Prover side.
        let mut transcript = prover_transcript(rounds);
        let mut prover = Prover::new(&pc_gens, &mut transcript);
        constrain_prover(
            &mut prover,
            &circuit(&params, hash, Some(Scalar::from(PREIMAGE))),
            Scalar::from(PREIMAGE_BLINDING),
        )
        .expect("add prover constraints");
        let prover_metrics = prover.metrics();

        assert_eq!(prover_metrics.multipliers, multiplier_count(rounds));
        assert_eq!(prover_metrics.constraints, constraint_count(rounds));

        // Verifier side. Only the commitment points matter for the count, so
        // the preimage blinding is irrelevant here.
        let commitments = MimcCommitments {
            public_hash: public_hash_commitment(&pc_gens, hash),
            preimage: pc_gens
                .commit(Scalar::from(PREIMAGE), Scalar::zero())
                .compress(),
        };
        let mut transcript = verifier_transcript(rounds);
        let mut verifier = Verifier::new(&mut transcript);
        constrain_verifier(&pc_gens, &mut verifier, &params, hash, &commitments)
            .expect("add verifier constraints");
        let verifier_metrics = verifier.metrics();

        assert_eq!(verifier_metrics.multipliers, prover_metrics.multipliers);
        assert_eq!(verifier_metrics.constraints, prover_metrics.constraints);
    }
}
