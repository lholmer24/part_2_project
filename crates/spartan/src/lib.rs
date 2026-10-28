//! Spartan proof of knowledge of a MiMC preimage over Ristretto255.
//!
//! Not done yet.

pub mod circuit;

use spartan_lib::{
    ComputationCommitment, ComputationDecommitment, InputsAssignment, Instance, SNARKGens,
    VarsAssignment, SNARK,
};

pub use circuit::MimcPreimageCircuit;
pub use mimc::MimcParams;

/// The encoded R1CS instance and generators.
pub struct SpartanParams {
    /// SNARK generators.
    pub gens: SNARKGens,
    /// Encoded R1CS instance.
    pub instance: Instance,
    /// Commitment to the instance.
    pub commitment: ComputationCommitment,
    /// Decommitment for the instance.
    pub decommitment: ComputationDecommitment,
}

/// Errors from the Spartan wrapper.
#[derive(Debug)]
pub enum Error {
    /// Setup failed.
    Setup,
    /// Verification failed.
    Verification,
}

/// Encode the circuit as an R1CS instance and build the generators.
pub fn setup(_circuit: &MimcPreimageCircuit) -> Result<SpartanParams, Error> {
    todo!("Spartan setup is not done yet")
}

/// Create a Spartan proof.
pub fn prove(_params: &SpartanParams, _vars: VarsAssignment, _inputs: &InputsAssignment) -> SNARK {
    todo!("Spartan proving is not done yet")
}

/// Verify a Spartan proof.
pub fn verify(
    _params: &SpartanParams,
    _proof: &SNARK,
    _inputs: &InputsAssignment,
) -> Result<(), Error> {
    todo!("Spartan verification is not done yet")
}
