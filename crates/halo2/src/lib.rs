//! Halo2 proof of knowledge of a MiMC preimage over Pasta.
//!
//! Not done yet.

pub mod circuit;

use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{Error, ProvingKey, VerifyingKey},
    poly::commitment::Params,
};
use rand_core::Rng;

pub use circuit::MimcPreimageCircuit;
pub use mimc::MimcParams;

/// The public parameters and keys for one circuit shape.
pub struct Halo2Params {
    /// IPA public parameters.
    pub params: Params<EqAffine>,
    /// Verifying key.
    pub verifying_key: VerifyingKey<EqAffine>,
    /// Proving key.
    pub proving_key: ProvingKey<EqAffine>,
}

/// Generate the keys for the circuit.
pub fn setup(_k: u32, _circuit: &MimcPreimageCircuit) -> Result<Halo2Params, Error> {
    todo!("Halo2 setup is not done yet")
}

/// Create a Halo2 proof.
pub fn prove(
    _params: &Halo2Params,
    _circuit: MimcPreimageCircuit,
    _instances: &[&[&[Fp]]],
    _rng: impl Rng,
) -> Result<Vec<u8>, Error> {
    todo!("Halo2 proving is not done yet")
}

/// Verify a Halo2 proof.
pub fn verify(_params: &Halo2Params, _proof: &[u8], _instances: &[&[&[Fp]]]) -> Result<(), Error> {
    todo!("Halo2 verification is not done yet")
}
