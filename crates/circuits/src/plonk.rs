//! The MiMC preimage statement as a PLONK circuit.
//!
//! Not done yet.

use dusk_plonk::prelude::{BlsScalar, Circuit, Composer, Error};

/// PLONK circuit for the MiMC preimage statement.
///
/// The shared circuit type is aliased with the PLONK field.
pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<BlsScalar>;

impl Circuit for MimcPreimageCircuit {
    fn circuit(&self, _composer: &mut Composer) -> Result<(), Error> {
        todo!("PLONK gate encoding is not done yet")
    }
}
