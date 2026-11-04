//! Groth16 adapter for the benchmark harness.

use std::time::Instant;

use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;

use groth16::{Groth16Params, MimcParams, MimcPreimageCircuit};

use crate::{BoxError, ProofSample, System};

/// Preimage used for every Groth16 benchmark statement.
const PREIMAGE: u64 = 12345;

struct Prepared {
    mimc: MimcParams<Fr>,
    hash: Fr,
    preimage: Fr,
    groth16: Option<Groth16Params>,
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
        "bls12_381_fr"
    }

    fn prepare(&mut self, rounds: usize) -> Result<(), BoxError> {
        let mimc =
            MimcParams::<Fr>::load(rounds, 5).map_err(|error| -> BoxError { Box::new(error) })?;
        let preimage = Fr::from(PREIMAGE);
        let hash = mimc::hash(&mimc, preimage);

        self.prepared = Some(Prepared {
            mimc,
            hash,
            preimage,
            groth16: None,
        });
        Ok(())
    }

    fn setup(&mut self, _rounds: usize) -> Result<(), BoxError> {
        let mimc = match &self.prepared {
            Some(prepared) => prepared.mimc.clone(),
            None => return Err("groth16 prepare was not run".into()),
        };
        let mut rng = ark_std::test_rng();
        let groth16 =
            groth16::setup(mimc, &mut rng).map_err(|error| -> BoxError { Box::new(error) })?;

        if let Some(prepared) = &mut self.prepared {
            prepared.groth16 = Some(groth16);
        }
        Ok(())
    }

    fn measure(&self, _rounds: usize) -> Result<ProofSample, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("groth16 prepare was not run".into()),
        };
        let params = match &prepared.groth16 {
            Some(params) => params,
            None => return Err("groth16 setup was not run".into()),
        };

        // Circuit synthesis and witness construction are inside the prove timer
        // and inside the library prover call.
        let circuit = MimcPreimageCircuit {
            params: prepared.mimc.clone(),
            hash: prepared.hash,
            preimage: Some(prepared.preimage),
        };
        let mut rng = ark_std::test_rng();

        let start = Instant::now();
        let proof = groth16::prove(params, circuit, &mut rng)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let prove_time = start.elapsed();

        let mut bytes: Vec<u8> = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let proof_size = bytes.len();

        let start = Instant::now();
        let valid = groth16::verify(params, prepared.hash, &proof)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let verify_time = start.elapsed();

        if !valid {
            return Err("groth16 proof did not verify".into());
        }

        Ok(ProofSample {
            proof_size,
            prove_time,
            verify_time,
        })
    }
}
