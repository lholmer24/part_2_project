//! Trivial system used by harness tests. It is not registered, so a normal run
//! cannot write placeholder rows.

use crate::{BoxError, ProofBox, System};

#[derive(Clone, Debug, Default)]
pub struct PlaceholderSystem;

impl PlaceholderSystem {
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

    fn setup(&mut self) -> Result<(), BoxError> {
        Ok(())
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        Ok(ProofBox::new(0u8))
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        Ok(0)
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        Ok(true)
    }
}
