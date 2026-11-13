//! Adapters that connect each proof system to the harness.
//!
//! Unimplemented adapters are declared but not registered in the system list
//! until their `System` methods are complete.
//!
//! Every adapter must implement [`System::prepare_instance`](crate::System::prepare_instance)
//! with the shared uniform preimage sampler. Do not hard-code a benchmark
//! preimage; repeated statements reuse the STARK grinding draw.

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
