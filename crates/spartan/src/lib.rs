//! Spartan R1CS for the MiMC preimage statement over Ristretto255.
//!
//! This crate defines the circuit and the R1CS instance builder. The harness
//! adapter calls `spartan` directly.

pub mod circuit;

pub use circuit::{build_instance, Error, MimcInstance, MimcPreimageCircuit};
