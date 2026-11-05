//! Spartan adapter for the benchmark harness.
//!
//! Not done yet. The adapter will hold the `SNARKGens`, the encoded instance
//! and commitment, and the current MiMC statement.

use crate::{BoxError, ProofBox, System};

/// Harness adapter for Spartan over Ristretto255.
#[derive(Default)]
pub struct SpartanSystem;

impl SpartanSystem {
    /// Create an adapter with no prepared state.
    pub fn new() -> Self {
        Self
    }
}

impl System for SpartanSystem {
    fn name(&self) -> &str {
        "spartan"
    }

    fn field(&self) -> &str {
        "ristretto255_scalar"
    }

    fn prepare_universal(&mut self, _max_rounds: usize) -> Result<(), BoxError> {
        todo!("Spartan generators are not built yet")
    }

    fn prepare(&mut self, _rounds: usize) -> Result<(), BoxError> {
        todo!("Spartan preparation is not done yet")
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        todo!("Spartan instance encoding is not done yet")
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        todo!("Spartan proving is not done yet")
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        todo!("Spartan proof size is not measured yet")
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        todo!("Spartan verification is not done yet")
    }
}
