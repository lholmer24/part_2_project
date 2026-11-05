//! The MiMC preimage statement as a Bulletproofs R1CS.
//!
//! Not done yet.

use std::borrow::BorrowMut;

use bulletproofs_lib::r1cs::{Prover, R1CSError, Variable, Verifier};
use curve25519_dalek_v3::scalar::Scalar;
use merlin::Transcript;
use mimc::MimcParams;

/// Bulletproofs R1CS circuit for the MiMC preimage statement.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<Scalar>,
    /// Public hash, h.
    pub hash: Scalar,
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<Scalar>,
}

/// Add the MiMC statement to a Bulletproofs R1CS prover.
///
/// `public_hash` is the prover variable that holds the commitment to `h`.
/// The body is left for the implementation.
pub fn constrain_prover<T>(
    _prover: &mut Prover<'_, T>,
    _circuit: &MimcPreimageCircuit,
    _public_hash: Variable,
) -> Result<(), R1CSError>
where
    T: BorrowMut<Transcript>,
{
    todo!("Bulletproofs prover constraints are not done yet")
}

/// Add the MiMC statement to a Bulletproofs R1CS verifier.
///
/// `public_hash` is the verifier variable that holds the commitment to `h`.
/// The body is left for the implementation.
pub fn constrain_verifier<T>(
    _verifier: &mut Verifier<T>,
    _public_hash: Variable,
) -> Result<(), R1CSError>
where
    T: BorrowMut<Transcript>,
{
    todo!("Bulletproofs verifier constraints are not done yet")
}
