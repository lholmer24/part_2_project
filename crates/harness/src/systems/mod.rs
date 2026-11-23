//! Adapters that connect each proof system to the harness.

pub mod bulletproofs;
pub mod groth16;
pub mod halo2;
pub mod plonk;
pub mod spartan;
pub mod stark;

pub use bulletproofs::BulletproofsSystem;
pub use groth16::Groth16System;
pub use halo2::Halo2System;
pub use plonk::PlonkSystem;
pub use spartan::SpartanSystem;
pub use stark::StarkSystem;
