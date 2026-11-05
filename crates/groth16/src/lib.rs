//! Groth16 circuit for the MiMC preimage statement over BLS12-381.
//!
//! The benchmark adapter calls `ark-groth16` directly. This crate only defines
//! the statement as a constraint system, so the circuit can be tested alone.

pub mod circuit;

pub use circuit::MimcPreimageCircuit;
