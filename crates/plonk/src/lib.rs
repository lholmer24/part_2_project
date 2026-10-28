//! PLONK proof of knowledge of a MiMC preimage over BLS12-381.
//!
//! Not done yet.

pub mod circuit;

use dusk_plonk::prelude::{BlsScalar, Error, Proof, Prover, PublicParameters, Verifier};
use rand_core::{CryptoRng, RngCore};

pub use circuit::MimcPreimageCircuit;
pub use mimc::MimcParams;

/// The compiled circuit and the public parameters for one circuit shape.
pub struct PlonkParams {
    /// Universal public parameters.
    pub public_parameters: PublicParameters,
    /// Compiled prover.
    pub prover: Prover,
    /// Compiled verifier.
    pub verifier: Verifier,
}

/// Compile the circuit and prepare the prover and verifier.
pub fn setup(
    _circuit: &MimcPreimageCircuit,
    _rng: &mut (impl RngCore + CryptoRng),
) -> Result<PlonkParams, Error> {
    todo!("PLONK setup is not done yet")
}

/// Create a PLONK proof.
pub fn prove(
    _params: &PlonkParams,
    _circuit: &MimcPreimageCircuit,
    _rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof, Error> {
    todo!("PLONK proving is not done yet")
}

/// Verify a PLONK proof.
pub fn verify(
    _params: &PlonkParams,
    _proof: &Proof,
    _public_inputs: &[BlsScalar],
) -> Result<(), Error> {
    todo!("PLONK verification is not done yet")
}
