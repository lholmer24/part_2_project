//! Groth16 adapter for the benchmark harness.
//!
//! The adapter calls `ark-groth16` directly. It holds no timer, so the harness
//! times setup, proving and verification at one call boundary.

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, ProvingKey};
use ark_serialize::CanonicalSerialize;
use circuits::groth16::MimcPreimageCircuit;
use mimc::{MimcField, MimcParams, Statement};

use crate::{benchmark_seed, BoxError, ProofBox, System};

struct Keys {
    proving_key: ProvingKey<Bls12_381>,
    prepared_verifying_key: PreparedVerifyingKey<Bls12_381>,
}

struct Prepared {
    mimc: MimcParams<Fr>,
    hash: Fr,
    preimage: Fr,
    keys: Option<Keys>,
}

/// Harness adapter for Groth16 over BLS12-381.
#[derive(Default)]
pub struct Groth16System {
    prepared: Option<Prepared>,
}

impl Groth16System {
    /// Create an adapter with no prepared state.
    pub fn new() -> Self {
        Self::default()
    }
}

impl System for Groth16System {
    fn name(&self) -> &str {
        "groth16"
    }

    fn field(&self) -> &str {
        Fr::NAME
    }

    fn prepare(&mut self, rounds: usize) -> Result<(), BoxError> {
        let mimc =
            MimcParams::<Fr>::load(rounds, 5).map_err(|error| -> BoxError { Box::new(error) })?;
        let preimage = mimc::uniform_from_seed::<Fr>(&benchmark_seed(rounds, 0));
        let hash = mimc::hash(&mimc, preimage);

        self.prepared = Some(Prepared {
            mimc,
            hash,
            preimage,
            keys: None,
        });
        Ok(())
    }

    fn prepare_instance(&mut self, rounds: usize, instance: usize) -> Result<(), BoxError> {
        let prepared = match &mut self.prepared {
            Some(prepared) => prepared,
            None => return Err("groth16 prepare was not run".into()),
        };
        let preimage = mimc::uniform_from_seed::<Fr>(&benchmark_seed(rounds, instance));
        prepared.hash = mimc::hash(&prepared.mimc, preimage);
        prepared.preimage = preimage;
        Ok(())
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        let circuit = {
            let prepared = match &self.prepared {
                Some(prepared) => prepared,
                None => return Err("groth16 prepare was not run".into()),
            };
            MimcPreimageCircuit {
                statement: Statement {
                    params: prepared.mimc.clone(),
                    hash: prepared.hash,
                    preimage: None,
                },
            }
        };

        let mut rng = ark_std::test_rng();
        let proving_key =
            Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng)
                .map_err(|error| -> BoxError { Box::new(error) })?;
        let prepared_verifying_key = prepare_verifying_key(&proving_key.vk);

        match &mut self.prepared {
            Some(prepared) => {
                prepared.keys = Some(Keys {
                    proving_key,
                    prepared_verifying_key,
                });
                Ok(())
            }
            None => Err("groth16 prepare was not run".into()),
        }
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("groth16 prepare was not run".into()),
        };
        let keys = match &prepared.keys {
            Some(keys) => keys,
            None => return Err("groth16 setup was not run".into()),
        };

        let circuit = MimcPreimageCircuit {
            statement: Statement {
                params: prepared.mimc.clone(),
                hash: prepared.hash,
                preimage: Some(prepared.preimage),
            },
        };
        let mut rng = ark_std::test_rng();
        let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
            circuit,
            &keys.proving_key,
            &mut rng,
        )
        .map_err(|error| -> BoxError { Box::new(error) })?;

        Ok(ProofBox::new(proof))
    }

    fn proof_size(&self, proof: &ProofBox) -> Result<usize, BoxError> {
        let proof = proof
            .downcast_ref::<ark_groth16::Proof<Bls12_381>>()
            .ok_or("groth16 proof type mismatch")?;
        let mut bytes: Vec<u8> = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        Ok(bytes.len())
    }

    fn verify(&self, proof: &ProofBox) -> Result<bool, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("groth16 prepare was not run".into()),
        };
        let keys = match &prepared.keys {
            Some(keys) => keys,
            None => return Err("groth16 setup was not run".into()),
        };
        let proof = proof
            .downcast_ref::<ark_groth16::Proof<Bls12_381>>()
            .ok_or("groth16 proof type mismatch")?;

        Groth16::<Bls12_381>::verify_proof(&keys.prepared_verifying_key, proof, &[prepared.hash])
            .map_err(|error| -> BoxError { Box::new(error) })
    }
}
