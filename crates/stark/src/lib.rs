//! STARK circuit for the MiMC preimage statement over winterfell `f128`.
//!
//! This crate defines the AIR and the trace builder. The harness adapter calls
//! winterfell directly.

pub mod air;

use mimc::MimcParams;
use winterfell::{math::fields::f128::BaseElement, TraceTable};

pub use air::{MimcAir, MimcPublicInputs};

/// STARK circuit for the MiMC preimage statement.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<BaseElement>,
    /// Public hash, h.
    pub hash: BaseElement,
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<BaseElement>,
}

/// Build the execution trace for one MiMC statement.
///
/// The adapter calls this inside the timed `prove` call. The body is left for
/// the implementation.
pub fn build_trace(_circuit: &MimcPreimageCircuit) -> TraceTable<BaseElement> {
    todo!("STARK trace generation is not done yet")
}
