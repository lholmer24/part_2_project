//! STARK adapter for the benchmark harness.
//!
//! The adapter calls `winterfell` directly. It holds no timer, so the harness
//! times proving and verification at one call boundary.
//!
//! STARK is transparent: there is no per-configuration setup phase and no
//! universal parameters. [`System::prepare`](crate::System::prepare) loads the
//! round constants, computes the reference hash and builds the proof options.
//! The AIR and trace builder are in `circuits::stark`.

use circuits::stark::{self, MimcPreimageCircuit, MimcPublicInputs};
use mimc::field_names::WINTERFELL_F128;
use mimc::{MimcParams, Statement};
use winterfell::math::fields::f128::BaseElement;
use winterfell::{Proof, ProofOptions};

use crate::{BoxError, ProofBox, System};

/// Preimage used for every STARK benchmark statement.
const PREIMAGE: u64 = 12345;

struct Prepared {
    mimc: MimcParams<BaseElement>,
    hash: BaseElement,
    preimage: BaseElement,
    options: ProofOptions,
}

/// Harness adapter for STARK over winterfell `f128`.
#[derive(Default)]
pub struct StarkSystem {
    prepared: Option<Prepared>,
}

impl StarkSystem {
    /// Create an adapter with no prepared state.
    pub fn new() -> Self {
        Self::default()
    }
}

impl System for StarkSystem {
    fn name(&self) -> &str {
        "stark"
    }

    fn field(&self) -> &str {
        WINTERFELL_F128
    }

    fn prepare(&mut self, rounds: usize) -> Result<(), BoxError> {
        let mimc = MimcParams::<BaseElement>::load(rounds, 5)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let preimage = BaseElement::from(PREIMAGE);
        let hash = mimc::hash(&mimc, preimage);

        self.prepared = Some(Prepared {
            mimc,
            hash,
            preimage,
            options: stark::proof_options(),
        });
        Ok(())
    }

    fn has_setup(&self) -> bool {
        false
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        unreachable!("STARK has no setup phase")
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("stark prepare was not run".into()),
        };

        let circuit = MimcPreimageCircuit {
            statement: Statement {
                params: prepared.mimc.clone(),
                hash: prepared.hash,
                preimage: Some(prepared.preimage),
            },
        };
        let proof = stark::prove(&circuit, prepared.options.clone())
            .map_err(|error| -> BoxError { Box::new(error) })?;

        Ok(ProofBox::new(proof))
    }

    fn proof_size(&self, proof: &ProofBox) -> Result<usize, BoxError> {
        let proof = proof
            .downcast_ref::<Proof>()
            .ok_or("stark proof type mismatch")?;
        Ok(proof.to_bytes().len())
    }

    fn verify(&self, proof: &ProofBox) -> Result<bool, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("stark prepare was not run".into()),
        };
        let proof = proof
            .downcast_ref::<Proof>()
            .ok_or("stark proof type mismatch")?;
        let public_inputs = MimcPublicInputs::new(prepared.hash, prepared.mimc.rounds);

        // A rejected proof is a `false` result, not an adapter failure.
        Ok(stark::verify(proof.clone(), &public_inputs).is_ok())
    }
}
