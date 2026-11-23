//! Bulletproofs MiMC preimage circuit.
//!
//! Bulletproofs has no circuit trait: the prover and verifier must make the
//! same `ConstraintSystem` calls, so `constrain_mimc` is shared. One round
//! costs three multipliers:
//!
//! ```text
//! t2 = (s + c)(s + c)
//! t4 = t2^2
//! s' = t4(s + c)
//! ```
//!
//! Each multiplier adds two linear constraints and the finish equality
//! `s_r + x - h = 0` adds one, so `r` rounds cost `3r` multipliers and `6r + 1`
//! constraints.
//!
//! `h` is committed with zero blinding so the verifier can rebuild the
//! commitment from the expected hash; `x` uses a fresh random blinding. Both
//! sides must commit `h` first and `x` second, because the commitments enter
//! the transcript in that order.

use std::borrow::BorrowMut;

use bulletproofs_lib::r1cs::{ConstraintSystem, Prover, R1CSError, Variable, Verifier};
use bulletproofs_lib::PedersenGens;
use curve25519_dalek_v3::ristretto::CompressedRistretto;
use curve25519_dalek_v3::scalar::Scalar;
use merlin::Transcript;
use mimc::{MimcParams, Statement};

pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<Scalar>;

pub const MULTIPLIERS_PER_ROUND: usize = 3;

pub const CONSTRAINTS_PER_ROUND: usize = 2 * MULTIPLIERS_PER_ROUND;

pub const BASE_CONSTRAINTS: usize = 1;

pub fn multiplier_count(rounds: usize) -> usize {
    MULTIPLIERS_PER_ROUND * rounds
}

pub fn constraint_count(rounds: usize) -> usize {
    CONSTRAINTS_PER_ROUND * rounds + BASE_CONSTRAINTS
}

/// Smallest power-of-two capacity that covers `multipliers`.
pub fn generator_capacity(multipliers: usize) -> usize {
    multipliers.next_power_of_two()
}

#[derive(Clone, Debug)]
pub struct MimcCommitments {
    pub public_hash: CompressedRistretto,
    pub preimage: CompressedRistretto,
}

pub fn public_hash_commitment(pc_gens: &PedersenGens, hash: Scalar) -> CompressedRistretto {
    pc_gens.commit(hash, Scalar::zero()).compress()
}

pub fn constrain_mimc<CS: ConstraintSystem>(
    cs: &mut CS,
    params: &MimcParams<Scalar>,
    public_hash: Variable,
    preimage: Variable,
) -> Result<(), R1CSError> {
    if params.exponent != 5 {
        return Err(R1CSError::GadgetError {
            description: "only exponent 5 is supported".to_string(),
        });
    }

    let mut state = preimage;

    for constant in params.round_constants.iter() {
        let sum = state + *constant;
        let (_, _, t1) = cs.multiply(sum.clone(), sum.clone());
        let (_, _, t2) = cs.multiply(t1.into(), t1.into());
        let (_, _, t3) = cs.multiply(t2.into(), sum);
        state = t3;
    }
    cs.constrain(state + preimage - public_hash);
    Ok(())
}

/// Measured circuit size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitSize {
    pub multipliers: usize,
    pub constraints: usize,
}

/// Measure the circuit so the adapter can size `BulletproofGens` from it.
pub fn circuit_size(params: &MimcParams<Scalar>) -> Result<CircuitSize, R1CSError> {
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"mimc-bulletproofs-size");
    let mut prover = Prover::new(&pc_gens, &mut transcript);
    let (_, public_hash) = prover.commit(Scalar::zero(), Scalar::zero());
    let (_, preimage) = prover.commit(Scalar::zero(), Scalar::zero());

    constrain_mimc(&mut prover, params, public_hash, preimage)?;
    let metrics = prover.metrics();

    Ok(CircuitSize {
        multipliers: metrics.multipliers,
        constraints: metrics.constraints,
    })
}

pub fn constrain_prover<T>(
    prover: &mut Prover<'_, T>,
    circuit: &MimcPreimageCircuit,
    preimage_blinding: Scalar,
) -> Result<MimcCommitments, R1CSError>
where
    T: BorrowMut<Transcript>,
{
    let Statement {
        params,
        hash,
        preimage,
    } = &circuit.statement;
    let preimage = preimage.ok_or(R1CSError::MissingAssignment)?;

    // Transcript order: the verifier commits in this order too.
    let (public_hash, public_hash_var) = prover.commit(*hash, Scalar::zero());
    let (preimage_commitment, preimage_var) = prover.commit(preimage, preimage_blinding);

    constrain_mimc(prover, params, public_hash_var, preimage_var)?;

    Ok(MimcCommitments {
        public_hash,
        preimage: preimage_commitment,
    })
}

pub fn constrain_verifier<T>(
    pc_gens: &PedersenGens,
    verifier: &mut Verifier<T>,
    params: &MimcParams<Scalar>,
    hash: Scalar,
    commitments: &MimcCommitments,
) -> Result<(), R1CSError>
where
    T: BorrowMut<Transcript>,
{
    if public_hash_commitment(pc_gens, hash) != commitments.public_hash {
        return Err(R1CSError::VerificationError);
    }

    // Same order as `constrain_prover`.
    let public_hash_var = verifier.commit(commitments.public_hash);
    let preimage_var = verifier.commit(commitments.preimage);

    constrain_mimc(verifier, params, public_hash_var, preimage_var)
}
