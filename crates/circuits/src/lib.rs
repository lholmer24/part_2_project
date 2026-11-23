//! MiMC preimage circuits, one module per proof system.

use mimc::Statement;

#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit<F> {
    pub statement: Statement<F>,
}

pub mod bulletproofs;
pub mod groth16;
pub mod halo2;
pub mod plonk;
pub mod spartan;
pub mod stark;
