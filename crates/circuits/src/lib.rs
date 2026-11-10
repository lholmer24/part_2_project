//! MiMC preimage circuits for every benchmarked proof system.
//!
//! Each module holds one statement encoding as a single file. The harness
//! adapters in `crates/harness/src/systems/` call the proof-system libraries
//! directly.

use mimc::Statement;

/// MiMC preimage circuit shared by every system.
///
/// Each system aliases this type with its native field, then implements its
/// own proof-system trait. The statement itself is defined once in
/// [`mimc::Statement`].
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit<F> {
    /// The MiMC statement.
    pub statement: Statement<F>,
}

pub mod bulletproofs;
pub mod groth16;
pub mod halo2;
pub mod plonk;
pub mod spartan;
pub mod stark;
