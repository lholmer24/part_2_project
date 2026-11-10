//! PLONK adapter for the benchmark harness.
//!
//! The adapter calls `dusk-plonk` directly. It holds no timer, so the harness
//! times setup, proving and verification at one call boundary.
//!
//! The universal KZG parameters are built once in
//! [`System::prepare_universal`](crate::System::prepare_universal) and are not
//! reset by [`System::prepare`](crate::System::prepare).

use circuits::plonk::MimcPreimageCircuit;
use dusk_bytes::Serializable;
use dusk_plonk::prelude::{BlsScalar, Compiler, Proof, Prover, PublicParameters, Verifier};
use mimc::field_names::BLS12_381_FR;
use mimc::{MimcParams, Statement};
use rand_core::OsRng;

use crate::{BoxError, ProofBox, System};

/// Preimage used for every PLONK benchmark statement.
const PREIMAGE: u64 = 12345;

/// Domain-separation label for the compiled circuit.
const LABEL: &[u8] = b"mimc-plonk-v1";

struct Prepared {
    mimc: MimcParams<BlsScalar>,
    hash: BlsScalar,
    preimage: BlsScalar,
    keys: Option<(Prover, Verifier)>,
}

/// A PLONK proof plus the public inputs that the prover extracted from the
/// circuit. The verifier needs both.
struct PlonkProof {
    proof: Proof,
    public_inputs: Vec<BlsScalar>,
}

/// Harness adapter for PLONK over BLS12-381.
pub struct PlonkSystem {
    public_parameters: Option<PublicParameters>,
    prepared: Option<Prepared>,
}

impl PlonkSystem {
    /// Create an adapter with no prepared state.
    pub fn new() -> Self {
        Self {
            public_parameters: None,
            prepared: None,
        }
    }
}

impl Default for PlonkSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl System for PlonkSystem {
    fn name(&self) -> &str {
        "plonk"
    }

    fn field(&self) -> &str {
        BLS12_381_FR
    }

    fn prepare_universal(&mut self, max_rounds: usize) -> Result<(), BoxError> {
        // The compiler trims the parameters to the next power of two above the
        // circuit's gate count, so the universal parameters must cover that
        // size for the largest configuration in the sweep.
        let max_degree = circuits::plonk::gate_count(max_rounds).next_power_of_two();
        let public_parameters = PublicParameters::setup(max_degree, &mut OsRng)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        self.public_parameters = Some(public_parameters);
        Ok(())
    }

    fn prepare(&mut self, rounds: usize) -> Result<(), BoxError> {
        let mimc = MimcParams::<BlsScalar>::load(rounds, 5)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let preimage = BlsScalar::from(PREIMAGE);
        let hash = mimc::hash(&mimc, preimage);

        self.prepared = Some(Prepared {
            mimc,
            hash,
            preimage,
            keys: None,
        });
        Ok(())
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        let circuit = {
            let prepared = match &self.prepared {
                Some(prepared) => prepared,
                None => return Err("plonk prepare was not run".into()),
            };
            MimcPreimageCircuit {
                statement: Statement {
                    params: prepared.mimc.clone(),
                    hash: prepared.hash,
                    // Shape only: the compiler ignores witness values.
                    preimage: None,
                },
            }
        };

        let public_parameters = match &self.public_parameters {
            Some(public_parameters) => public_parameters,
            None => return Err("plonk universal parameters were not built".into()),
        };
        let (prover, verifier) = Compiler::compile_with_circuit(public_parameters, LABEL, &circuit)
            .map_err(|error| -> BoxError { Box::new(error) })?;

        match &mut self.prepared {
            Some(prepared) => {
                prepared.keys = Some((prover, verifier));
                Ok(())
            }
            None => Err("plonk prepare was not run".into()),
        }
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("plonk prepare was not run".into()),
        };
        let keys = match &prepared.keys {
            Some(keys) => keys,
            None => return Err("plonk setup was not run".into()),
        };

        let circuit = MimcPreimageCircuit {
            statement: Statement {
                params: prepared.mimc.clone(),
                hash: prepared.hash,
                preimage: Some(prepared.preimage),
            },
        };
        let (proof, public_inputs) = keys
            .0
            .prove(&mut OsRng, &circuit)
            .map_err(|error| -> BoxError { Box::new(error) })?;

        Ok(ProofBox::new(PlonkProof {
            proof,
            public_inputs,
        }))
    }

    fn proof_size(&self, proof: &ProofBox) -> Result<usize, BoxError> {
        let proof = proof
            .downcast_ref::<PlonkProof>()
            .ok_or("plonk proof type mismatch")?;
        Ok(proof.proof.to_bytes().len())
    }

    fn verify(&self, proof: &ProofBox) -> Result<bool, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("plonk prepare was not run".into()),
        };
        let keys = match &prepared.keys {
            Some(keys) => keys,
            None => return Err("plonk setup was not run".into()),
        };
        let proof = proof
            .downcast_ref::<PlonkProof>()
            .ok_or("plonk proof type mismatch")?;

        // Verification errors mean the proof is rejected, so report them as
        // `false` instead of an adapter failure.
        Ok(keys.1.verify(&proof.proof, &proof.public_inputs).is_ok())
    }
}
