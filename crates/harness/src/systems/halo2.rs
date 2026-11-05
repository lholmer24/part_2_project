//! Halo2 adapter for the benchmark harness.
//!
//! Not done yet. The adapter will hold the IPA `Params`, the proving and
//! verifying keys, and the current MiMC statement.

use crate::{BoxError, ProofBox, System};

/// Harness adapter for Halo2 over Pasta.
#[derive(Default)]
pub struct Halo2System;

impl Halo2System {
    /// Create an adapter with no prepared state.
    pub fn new() -> Self {
        Self
    }
}

impl System for Halo2System {
    fn name(&self) -> &str {
        "halo2"
    }

    fn field(&self) -> &str {
        "pasta_fp"
    }

    fn prepare_universal(&mut self, _max_rounds: usize) -> Result<(), BoxError> {
        todo!("Halo2 IPA parameters are not built yet")
    }

    fn prepare(&mut self, _rounds: usize) -> Result<(), BoxError> {
        todo!("Halo2 preparation is not done yet")
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        todo!("Halo2 key generation is not done yet")
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        todo!("Halo2 proving is not done yet")
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        todo!("Halo2 proof size is not measured yet")
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        todo!("Halo2 verification is not done yet")
    }
}
