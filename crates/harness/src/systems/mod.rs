//! Adapters that connect each proof system to the harness.
//!
//! Every adapter is registered in [`crate::systems()`] once its `System`
//! methods are complete.
//!
//! Every adapter must implement [`System::prepare_instance`](crate::System::prepare_instance)
//! with the shared uniform preimage sampler. Do not hard-code a benchmark
//! preimage, so that no two samples repeat the same statement.

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
