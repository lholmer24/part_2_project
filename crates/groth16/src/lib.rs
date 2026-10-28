//! Groth16 proof of knowledge of a MiMC preimage over BLS12-381.
//!
//! This crate is a scaffold. The MiMC parameter choice and the constraint
//! encoding are core project work and are intentionally left unimplemented.

pub mod circuit;

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::gr1cs::SynthesisError;
use ark_std::rand::Rng;

pub use circuit::{MimcParams, MimcPreimageCircuit};

/// The concrete Groth16 instantiation used by this crate.
pub type Groth16Bls12_381 = Groth16<Bls12_381>;

/// The circuit-specific common reference string and the verifying key.
pub struct Groth16Params {
    /// Proving key produced by the trusted setup.
    pub proving_key: ProvingKey<Bls12_381>,
    /// Verifying key produced by the trusted setup.
    pub verifying_key: VerifyingKey<Bls12_381>,
    /// Verifying key prepared for repeated verification.
    pub prepared_verifying_key: PreparedVerifyingKey<Bls12_381>,
}

/// Run the circuit-specific trusted setup for a fixed MiMC parameter set.
pub fn setup(_params: MimcParams, _rng: &mut impl Rng) -> Result<Groth16Params, SynthesisError> {
    todo!("run the Groth16 trusted setup")
}

/// Create a proof for the given circuit instance.
pub fn prove(
    _params: &Groth16Params,
    _circuit: MimcPreimageCircuit,
    _rng: &mut impl Rng,
) -> Result<Proof<Bls12_381>, SynthesisError> {
    todo!("create a Groth16 proof")
}

/// Verify a proof against the public hash.
pub fn verify(
    _params: &Groth16Params,
    _public_hash: Fr,
    _proof: &Proof<Bls12_381>,
) -> Result<bool, SynthesisError> {
    todo!("verify a Groth16 proof")
}
