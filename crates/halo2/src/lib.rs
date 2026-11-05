//! Halo2 circuit for the MiMC preimage statement over Pasta.
//!
//! This crate defines the circuit only. The harness adapter calls
//! `halo2_proofs` directly.

pub mod circuit;

pub use circuit::MimcPreimageCircuit;
