//! The MiMC preimage statement as a Bulletproofs R1CS.
//!
//! Not done yet.

use curve25519_dalek::scalar::Scalar;
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
