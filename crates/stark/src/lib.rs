//! STARK proof of knowledge of a MiMC preimage over winterfell `f128`.
//!
//! Not done yet.

pub mod air;

use winterfell::{
    math::fields::f128::BaseElement, Proof, ProofOptions, ProverError, VerifierError,
};

pub use air::{MimcAir, MimcPublicInputs};
pub use mimc::MimcParams;

/// STARK circuit for the MiMC preimage statement.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<BaseElement>,
    /// Public hash, h.
    pub hash: BaseElement,
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<BaseElement>,
}

/// The AIR and proof options for one circuit shape.
pub struct StarkParams {
    /// Proof options.
    pub options: ProofOptions,
    /// AIR instance.
    pub air: MimcAir,
}

/// Error from STARK setup.
#[derive(Debug)]
pub struct SetupError;

/// Prepare the AIR and proof options.
pub fn setup(
    _params: MimcParams<BaseElement>,
    _options: ProofOptions,
) -> Result<StarkParams, SetupError> {
    todo!("STARK setup is not done yet")
}

/// Create a STARK proof.
pub fn prove(_params: &StarkParams, _circuit: &MimcPreimageCircuit) -> Result<Proof, ProverError> {
    todo!("STARK proving is not done yet")
}

/// Verify a STARK proof.
pub fn verify(
    _params: &StarkParams,
    _proof: &Proof,
    _public_inputs: &MimcPublicInputs,
) -> Result<(), VerifierError> {
    todo!("STARK verification is not done yet")
}
