//! PLONK circuit for the MiMC preimage statement over BLS12-381.
//!
//! This crate defines the circuit only. The harness adapter calls `dusk-plonk`
//! directly so the timed calls stay visible in one place.

pub mod circuit;

pub use circuit::MimcPreimageCircuit;
