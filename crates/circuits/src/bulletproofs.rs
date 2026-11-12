//! The MiMC preimage statement as a Bulletproofs R1CS.
//!
//! Bulletproofs has no `Circuit` trait. A statement is defined by calling the
//! same sequence of [`ConstraintSystem`] operations in the prover and in the
//! verifier, so `constrain_mimc` is shared by both sides.
//!
//! One MiMC round `s -> (s + c)^5` costs three multipliers:
//!
//! ```text
//! t2 = (s + c) * (s + c)
//! t4 = t2 * t2
//! s' = t4 * (s + c)
//! ```
//!
//! [`ConstraintSystem::multiply`] adds two linear constraints per multiplier.
//! The final equality `state + x - h = 0` adds one more, so `r` rounds cost
//! `3r` multipliers and `6r + 1` linear constraints.
//!
//! # Variables
//!
//! `h` and `x` are high-level committed variables, not low-level allocated
//! wires. The prover commits `h` with zero blinding and `x` with a random
//! blinding. The verifier rebuilds the `h` commitment from the public hash,
//! so a wrong `h` is rejected before any constraints are checked. The `x`
//! commitment is passed from the prover to the verifier unchanged.
//!
//! Commitments are appended to the transcript by
//! [`Prover::commit`]/[`Verifier::commit`], so the prover must commit `h`
//! first and `x` second to match the verifier.

use std::borrow::BorrowMut;

use bulletproofs_lib::r1cs::{ConstraintSystem, Prover, R1CSError, Variable, Verifier};
use bulletproofs_lib::PedersenGens;
use curve25519_dalek_v3::ristretto::CompressedRistretto;
use curve25519_dalek_v3::scalar::Scalar;
use merlin::Transcript;
use mimc::{MimcParams, Statement};

/// Bulletproofs R1CS circuit for the MiMC preimage statement.
///
/// The shared circuit type is aliased with the Bulletproofs field.
pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<Scalar>;

/// Multipliers that one MiMC round costs in the addition chain above.
pub const MULTIPLIERS_PER_ROUND: usize = 3;

/// Linear constraints that one MiMC round costs.
///
/// Each multiplier adds a constraint on its left input and one on its right
/// input.
pub const CONSTRAINTS_PER_ROUND: usize = 2 * MULTIPLIERS_PER_ROUND;

/// Linear constraints outside the round loop: the final equality
/// `state + x - h = 0`.
pub const BASE_CONSTRAINTS: usize = 1;

/// Expected multiplier count for `rounds` MiMC rounds.
pub fn multiplier_count(rounds: usize) -> usize {
    MULTIPLIERS_PER_ROUND * rounds
}

/// Expected linear-constraint count for `rounds` MiMC rounds.
pub fn constraint_count(rounds: usize) -> usize {
    CONSTRAINTS_PER_ROUND * rounds + BASE_CONSTRAINTS
}

/// Smallest power-of-two generator capacity that covers `max_rounds`.
///
/// [`Prover::prove`] and [`Verifier::verify`] need
/// `bp_gens.gens_capacity >= multiplier_count(rounds).next_power_of_two()`.
pub fn multiplier_capacity(max_rounds: usize) -> usize {
    multiplier_count(max_rounds).next_power_of_two()
}

/// Commitments that the prover hands to the verifier.
#[derive(Clone, Debug)]
pub struct MimcCommitments {
    /// Pedersen commitment to the public hash, with zero blinding.
    pub public_hash: CompressedRistretto,
    /// Pedersen commitment to the private preimage, with a random blinding.
    pub preimage: CompressedRistretto,
}

/// Deterministic commitment to the public hash.
///
/// Zero blinding makes the commitment a function of the hash only, so the
/// verifier can rebuild it from the hash value it expects.
pub fn public_hash_commitment(pc_gens: &PedersenGens, hash: Scalar) -> CompressedRistretto {
    pc_gens.commit(hash, Scalar::zero()).compress()
}

/// Add the MiMC constraints to a prover or verifier constraint system.
///
/// `public_hash` and `preimage` are the high-level variables returned by
/// `commit`. Both sides must call this with the same parameters and in the
/// same variable order. The bodies are left for the implementation.
///
/// Only exponent 5 is supported: the addition chain above is specific to
/// `e = 5`.
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

/// Commit the statement and add its constraints to a prover.
///
/// The prover commits the public hash with zero blinding, commits the
/// preimage with `preimage_blinding`, then calls [`constrain_mimc`]. It
/// returns the commitments that the verifier must insert into its own
/// constraint system.
///
/// `circuit.statement.preimage` must be `Some`; a missing witness returns
/// [`R1CSError::MissingAssignment`].
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

    // Order matters: the verifier must commit in the same order.
    let (public_hash, public_hash_var) = prover.commit(*hash, Scalar::zero());
    let (preimage_commitment, preimage_var) = prover.commit(preimage, preimage_blinding);

    constrain_mimc(prover, params, public_hash_var, preimage_var)?;

    Ok(MimcCommitments {
        public_hash,
        preimage: preimage_commitment,
    })
}

/// Rebuild the statement and add its constraints to a verifier.
///
/// The public hash is bound by rebuilding its zero-blinding commitment from
/// `hash`. A commitment that does not match is rejected with
/// [`R1CSError::VerificationError`].
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
