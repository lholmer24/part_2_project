//! PLONK adapter for the benchmark harness.
//!
//! Not done yet. The adapter will hold the universal `PublicParameters`, the
//! compiled `Prover` and `Verifier`, and the current MiMC statement. The
//! circuit is `circuits::plonk::MimcPreimageCircuit`.

use crate::{BoxError, ProofBox, System};

/// Harness adapter for PLONK over BLS12-381.
#[derive(Default)]
pub struct PlonkSystem;

impl PlonkSystem {
    /// Create an adapter with no prepared state.
    pub fn new() -> Self {
        Self
    }
}

impl System for PlonkSystem {
    fn name(&self) -> &str {
        "plonk"
    }

    fn field(&self) -> &str {
        "bls12_381_fr"
    }

    fn prepare_universal(&mut self, _max_rounds: usize) -> Result<(), BoxError> {
        todo!("PLONK universal parameters are not built yet")
    }

    fn prepare(&mut self, _rounds: usize) -> Result<(), BoxError> {
        todo!("PLONK preparation is not done yet")
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        todo!("PLONK setup is not done yet")
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        todo!("PLONK proving is not done yet")
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        todo!("PLONK proof size is not measured yet")
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        todo!("PLONK verification is not done yet")
    }
}
