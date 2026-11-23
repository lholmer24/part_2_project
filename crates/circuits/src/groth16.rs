//! Groth16 MiMC preimage circuit.
//!
//! Each round is `s' = (s + c)^5`, which `pow_by_constant([5])` encodes with
//! three multiplication constraints. The finish constraint is `s_r + x = h`,
//! so `r` rounds cost `3r + 1` constraints.

use ark_bls12_381::Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use mimc::Statement;

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
