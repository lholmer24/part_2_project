//! Bulletproofs proof of knowledge of a MiMC preimage over Ristretto255.
//!
//! Not done yet.

pub mod circuit;

use bulletproofs_lib::{
    r1cs::{R1CSError, R1CSProof},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek::scalar::Scalar;

pub use circuit::MimcPreimageCircuit;
pub use mimc::MimcParams;

/// Generators for the R1CS proof.
pub struct BulletproofsParams {
    /// Pedersen commitment generators.
    pub pc_gens: PedersenGens,
    /// Bulletproofs vector commitment generators.
    pub bp_gens: BulletproofGens,
}

/// Prepare the generators for one circuit shape.
pub fn setup(_circuit: &MimcPreimageCircuit) -> BulletproofsParams {
    todo!("Bulletproofs setup is not done yet")
}

/// Create a Bulletproofs R1CS proof.
pub fn prove(
    _params: &BulletproofsParams,
    _circuit: &MimcPreimageCircuit,
) -> Result<R1CSProof, R1CSError> {
    todo!("Bulletproofs proving is not done yet")
}

/// Verify a Bulletproofs R1CS proof.
pub fn verify(
    _params: &BulletproofsParams,
    _public_hash: Scalar,
    _proof: &R1CSProof,
) -> Result<(), R1CSError> {
    todo!("Bulletproofs verification is not done yet")
}
