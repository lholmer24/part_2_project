//! Bulletproofs R1CS for the MiMC preimage statement over Ristretto255.
//!
//! This crate defines the circuit and the prover/verifier constraint builders.
//! The harness adapter calls the Bulletproofs R1CS API directly.

pub mod circuit;

pub use circuit::{constrain_prover, constrain_verifier, MimcPreimageCircuit};
