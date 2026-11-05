//! The MiMC preimage statement as a Spartan R1CS.
//!
//! Not done yet.

use curve25519_dalek_v4::scalar::Scalar;
use mimc::MimcParams;
use spartan_lib::{InputsAssignment, Instance, VarsAssignment};

/// Spartan R1CS circuit for the MiMC preimage statement.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<Scalar>,
    /// Public hash, h.
    pub hash: Scalar,
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<Scalar>,
}

/// R1CS instance and assignments for one MiMC statement.
pub struct MimcInstance {
    /// Sparse R1CS instance.
    pub instance: Instance,
    /// Witness assignment.
    pub vars: VarsAssignment,
    /// Public input assignment.
    pub inputs: InputsAssignment,
}

/// Errors from the Spartan R1CS builder.
#[derive(Debug)]
pub enum Error {
    /// The R1CS instance or an assignment could not be built.
    R1CS,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Spartan R1CS construction failed")
    }
}

impl std::error::Error for Error {}

/// Build the R1CS instance and assignments for one MiMC statement.
///
/// The body is left for the implementation.
pub fn build_instance(_circuit: &MimcPreimageCircuit) -> Result<MimcInstance, Error> {
    todo!("Spartan R1CS construction is not done yet")
}
