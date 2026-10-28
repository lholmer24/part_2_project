//! Generic benchmark harness for the MiMC preimage statement.
//!
//! Not done yet.

use std::time::Duration;

/// One benchmark measurement.
#[derive(Clone, Debug)]
pub struct Measurement {
    /// Proof system name.
    pub system: String,
    /// Number of MiMC rounds.
    pub rounds: usize,
    /// Proof size in bytes.
    pub proof_size: usize,
    /// Setup time.
    pub setup_time: Duration,
    /// Prover time.
    pub prove_time: Duration,
    /// Verifier time.
    pub verify_time: Duration,
}

/// Run the benchmark sweep.
pub fn run() -> Result<Vec<Measurement>, Box<dyn std::error::Error>> {
    todo!("benchmark harness is not done yet")
}
