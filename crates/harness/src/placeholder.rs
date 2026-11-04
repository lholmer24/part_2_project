//! Trivial system used by harness tests.
//!
//! The placeholder does no real work. It exists so the harness can be tested
//! before a proof system is wired in.

use std::time::Duration;

use crate::{BoxError, ProofSample, System};

/// Placeholder proof system.
#[derive(Clone, Debug, Default)]
pub struct PlaceholderSystem;

impl PlaceholderSystem {
    /// Create the placeholder system.
    pub fn new() -> Self {
        Self
    }
}

impl System for PlaceholderSystem {
    fn name(&self) -> &str {
        "placeholder"
    }

    fn field(&self) -> &str {
        "none"
    }

    fn setup(&mut self, _rounds: usize) -> Result<(), BoxError> {
        Ok(())
    }

    fn measure(&self, _rounds: usize) -> Result<ProofSample, BoxError> {
        Ok(ProofSample {
            proof_size: 0,
            prove_time: Duration::ZERO,
            verify_time: Duration::ZERO,
        })
    }
}
