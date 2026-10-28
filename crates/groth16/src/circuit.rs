//! The MiMC preimage statement as a Groth16 constraint system.
//!
//! Skeleton only. The constraint encoding is core project work and is
//! intentionally left as `todo!()`.

use ark_bls12_381::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// MiMC parameters for one field and one round count.
#[derive(Clone, Debug)]
pub struct MimcParams {
    /// Number of rounds, r.
    pub rounds: usize,
    /// Round-function exponent, e, with gcd(e, q - 1) = 1.
    pub exponent: u64,
    /// Encryption key, k.
    pub key: Fr,
    /// Round constants c_0, ..., c_{r-1}.
    pub round_constants: Vec<Fr>,
}

/// Statement: knowledge of `preimage` such that `E_k(preimage) + preimage = hash`.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams,
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
