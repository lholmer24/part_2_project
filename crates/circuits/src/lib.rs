//! MiMC preimage circuits for every benchmarked proof system.
//!
//! Each module holds one statement encoding as a single file. The harness
//! adapters in `crates/harness/src/systems/` call the proof-system libraries
//! directly.

pub mod bulletproofs;
pub mod groth16;
pub mod halo2;
pub mod plonk;
pub mod spartan;
pub mod stark;
