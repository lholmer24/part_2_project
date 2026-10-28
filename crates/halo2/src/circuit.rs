//! The MiMC preimage statement as a Halo2 circuit.
//!
//! Not done yet.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    pasta::Fp,
    plonk::{Circuit, ConstraintSystem, Error},
};
use mimc::MimcParams;

/// Halo2 configuration for the MiMC circuit.
#[derive(Clone, Debug)]
pub struct Config;

/// Halo2 circuit for the MiMC preimage statement.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<Fp>,
    /// Public hash, h.
    pub hash: Fp,
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<Fp>,
}

impl Circuit<Fp> for MimcPreimageCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!("Halo2 witness removal is not done yet")
    }

    fn configure(_meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        todo!("Halo2 gate configuration is not done yet")
    }

    fn synthesize(&self, _config: Self::Config, _layouter: impl Layouter<Fp>) -> Result<(), Error> {
        todo!("Halo2 synthesis is not done yet")
    }
}
