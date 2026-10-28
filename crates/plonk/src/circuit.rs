//! The MiMC preimage statement as a PLONK circuit.
//!
//! Not done yet.

use dusk_plonk::prelude::{BlsScalar, Circuit, Composer, Error};
use mimc::MimcParams;

/// PLONK circuit for the MiMC preimage statement.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<BlsScalar>,
    /// Public hash, h.
    pub hash: BlsScalar,
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<BlsScalar>,
}

impl Circuit for MimcPreimageCircuit {
    fn circuit(&self, _composer: &mut Composer) -> Result<(), Error> {
        todo!("PLONK gate encoding is not done yet")
    }
}
