//! STARK adapter for the benchmark harness.
//!
//! Not done yet. The adapter will hold the proof options and the current MiMC
//! statement. It has no setup phase and no universal parameters. The AIR and
//! trace builder are in `circuits::stark`.

use crate::{BoxError, ProofBox, System};
use mimc::field_names::WINTERFELL_F128;

/// Harness adapter for STARK over winterfell `f128`.
#[derive(Default)]
pub struct StarkSystem;

impl StarkSystem {
    /// Create an adapter with no prepared state.
    pub fn new() -> Self {
        Self
    }
}

impl System for StarkSystem {
    fn name(&self) -> &str {
        "stark"
    }

    fn field(&self) -> &str {
        WINTERFELL_F128
    }

    fn prepare(&mut self, _rounds: usize) -> Result<(), BoxError> {
        todo!("STARK preparation is not done yet")
    }

    fn has_setup(&self) -> bool {
        false
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        unreachable!("STARK has no setup phase")
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        todo!("STARK proving is not done yet")
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        todo!("STARK proof size is not measured yet")
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        todo!("STARK verification is not done yet")
    }
}
