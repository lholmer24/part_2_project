//! The MiMC preimage statement as a Groth16 constraint system.
//!
//! The circuit has one public input, `h`, and the private witness `x`.
//! The constraints enforce `h = E(x) + x` over the parameters' rounds.

use ark_bls12_381::Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use mimc::Statement;

/// Groth16 circuit for the MiMC preimage statement.
///
/// The shared circuit type is aliased with the Groth16 field.
pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<Fr>;

impl ConstraintSynthesizer<Fr> for MimcPreimageCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let Statement {
            params,
            hash,
            preimage,
        } = self.statement;

        let public_hash = FpVar::new_input(cs.clone(), || Ok(hash))?;
        let secret = FpVar::new_witness(cs.clone(), || {
            preimage.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut state = secret.clone();
        for constant in params.round_constants.iter() {
            state = (state + *constant).pow_by_constant([params.exponent])?;
        }

        (state + secret).enforce_equal(&public_hash)?;
        Ok(())
    }
}
