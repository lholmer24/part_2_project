//! The MiMC preimage statement as a Spartan R1CS.
//!
//! Not done yet.

use mimc::MimcParams;

/// Spartan R1CS circuit for the MiMC preimage statement.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<[u8; 32]>,
    /// Public hash, h.
    pub hash: [u8; 32],
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<[u8; 32]>,
}
