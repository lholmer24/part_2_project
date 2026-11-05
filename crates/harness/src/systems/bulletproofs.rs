//! Bulletproofs adapter for the benchmark harness.
//!
//! Not done yet. The adapter will hold the Pedersen and Bulletproof generators
//! and the current MiMC statement. It has no setup phase. The circuit and R1CS
//! builders are in `circuits::bulletproofs`.

use crate::{BoxError, ProofBox, System};

/// Harness adapter for Bulletproofs over Ristretto255.
#[derive(Default)]
pub struct BulletproofsSystem;

impl BulletproofsSystem {
    /// Create an adapter with no prepared state.
    pub fn new() -> Self {
        Self
    }
}

impl System for BulletproofsSystem {
    fn name(&self) -> &str {
        "bulletproofs"
    }

    fn field(&self) -> &str {
        "ristretto255_scalar"
    }

    fn prepare_universal(&mut self, _max_rounds: usize) -> Result<(), BoxError> {
        todo!("Bulletproofs generators are not built yet")
    }

    fn prepare(&mut self, _rounds: usize) -> Result<(), BoxError> {
        todo!("Bulletproofs preparation is not done yet")
    }

    fn has_setup(&self) -> bool {
        false
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        unreachable!("Bulletproofs has no setup phase")
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        todo!("Bulletproofs proving is not done yet")
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        todo!("Bulletproofs proof size is not measured yet")
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        todo!("Bulletproofs verification is not done yet")
    }
}
