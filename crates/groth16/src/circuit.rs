//! The MiMC preimage statement as a Groth16 constraint system.
//!
//! Skeleton only. The constraint encoding is core project work and is
//! intentionally left as `todo!()`.

use ark_bls12_381::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use mimc::MimcParams;

/// Groth16 circuit for the MiMC preimage statement.
///
/// The parameter layout is shared through [`MimcParams`]. This local wrapper
/// exists because `ConstraintSynthesizer` is implemented once per system.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<Fr>,
    /// Public hash, h.
    pub hash: Fr,
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MimcPreimageCircuit {
    fn generate_constraints(self, _cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        todo!("encode the MiMC preimage statement as GR1CS constraints")
    }
}
