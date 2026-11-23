//! Halo2 adapter.
//!
//! IPA parameters cannot be trimmed, so one `Params` is cached per measured
//! domain exponent `k`; `prepare` selects the `k` for the current round count.

use std::collections::BTreeMap;

use circuits::halo2::{self, MimcPreimageCircuit};
use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use mimc::field_names::PASTA_FP;
use mimc::{MimcParams, Statement};
use rand_core_v10::UnwrapErr;
use rand_v10::rngs::SysRng;

use crate::{benchmark_seed, BoxError, ProofBox, System};

type Keys = (ProvingKey<EqAffine>, VerifyingKey<EqAffine>);

struct Prepared {
    mimc: MimcParams<Fp>,
    hash: Fp,
    preimage: Fp,
    /// Domain exponent measured for this round count.
    k: u32,
    keys: Option<Keys>,
}

pub struct Halo2System {
    params: BTreeMap<u32, Params<EqAffine>>,
    prepared: Option<Prepared>,
}

impl Halo2System {
    pub fn new() -> Self {
        Self {
            params: BTreeMap::new(),
            prepared: None,
        }
    }

    fn params(&self) -> Result<&Params<EqAffine>, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("halo2 prepare was not run".into()),
        };
        self.params
            .get(&prepared.k)
            .ok_or_else(|| format!("halo2 params for k = {} were not built", prepared.k).into())
    }
}

impl Default for Halo2System {
    fn default() -> Self {
        Self::new()
    }
}

impl System for Halo2System {
    fn name(&self) -> &str {
        "halo2"
    }

    fn field(&self) -> &str {
        PASTA_FP
    }

    fn prepare_universal(&mut self, max_rounds: usize) -> Result<(), BoxError> {
        // Measure the largest circuit rather than a layout formula.
        let mimc = MimcParams::<Fp>::load(max_rounds, 5)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let k_max = halo2::params_k(&mimc).map_err(|error| -> BoxError { Box::new(error) })?;

        // `Params::new` derives generators by hashing to the curve, so it needs
        // no RNG.
        self.params.clear();
        for k in 1..=k_max {
            self.params.insert(k, Params::new(k));
        }
        Ok(())
    }

    fn prepare(&mut self, rounds: usize) -> Result<(), BoxError> {
        let mimc =
            MimcParams::<Fp>::load(rounds, 5).map_err(|error| -> BoxError { Box::new(error) })?;
        let k = halo2::params_k(&mimc).map_err(|error| -> BoxError { Box::new(error) })?;
        let preimage = mimc::uniform_from_seed::<Fp>(&benchmark_seed(rounds, 0));
        let hash = mimc::hash(&mimc, preimage);

        self.prepared = Some(Prepared {
            mimc,
            hash,
            preimage,
            k,
            keys: None,
        });
        Ok(())
    }

    fn prepare_instance(&mut self, rounds: usize, instance: usize) -> Result<(), BoxError> {
        let prepared = match &mut self.prepared {
            Some(prepared) => prepared,
            None => return Err("halo2 prepare was not run".into()),
        };
        let preimage = mimc::uniform_from_seed::<Fp>(&benchmark_seed(rounds, instance));
        prepared.hash = mimc::hash(&prepared.mimc, preimage);
        prepared.preimage = preimage;
        Ok(())
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        let circuit = {
            let prepared = match &self.prepared {
                Some(prepared) => prepared,
                None => return Err("halo2 prepare was not run".into()),
            };
            MimcPreimageCircuit {
                statement: Statement {
                    params: prepared.mimc.clone(),
                    hash: prepared.hash,
                    // Shape only: key generation assigns no witness values.
                    preimage: None,
                },
            }
        };

        let params = self.params()?;
        let vk = keygen_vk(params, &circuit).map_err(|error| -> BoxError { Box::new(error) })?;
        let pk = keygen_pk(params, vk.clone(), &circuit)
            .map_err(|error| -> BoxError { Box::new(error) })?;

        match &mut self.prepared {
            Some(prepared) => {
                prepared.keys = Some((pk, vk));
                Ok(())
            }
            None => Err("halo2 prepare was not run".into()),
        }
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("halo2 prepare was not run".into()),
        };
        let keys = match &prepared.keys {
            Some(keys) => keys,
            None => return Err("halo2 setup was not run".into()),
        };
        let params = self.params()?;

        let circuit = MimcPreimageCircuit {
            statement: Statement {
                params: prepared.mimc.clone(),
                hash: prepared.hash,
                preimage: Some(prepared.preimage),
            },
        };
        let instance = [prepared.hash];
        let columns: [&[Fp]; 1] = [&instance];
        let instances: [&[&[Fp]]; 1] = [&columns];

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
        create_proof(
            params,
            &keys.0,
            &[circuit],
            &instances,
            UnwrapErr(SysRng),
            &mut transcript,
        )
        .map_err(|error| -> BoxError { Box::new(error) })?;

        Ok(ProofBox::new(transcript.finalize()))
    }

    fn proof_size(&self, proof: &ProofBox) -> Result<usize, BoxError> {
        let bytes = proof
            .downcast_ref::<Vec<u8>>()
            .ok_or("halo2 proof type mismatch")?;
        Ok(bytes.len())
    }

    fn verify(&self, proof: &ProofBox) -> Result<bool, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("halo2 prepare was not run".into()),
        };
        let keys = match &prepared.keys {
            Some(keys) => keys,
            None => return Err("halo2 setup was not run".into()),
        };
        let params = self.params()?;
        let bytes = proof
            .downcast_ref::<Vec<u8>>()
            .ok_or("halo2 proof type mismatch")?;

        let instance = [prepared.hash];
        let columns: [&[Fp]; 1] = [&instance];
        let instances: [&[&[Fp]]; 1] = [&columns];

        let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&bytes[..]);

        // A rejected or malformed proof is `false`, not an adapter failure.
        Ok(verify_proof(
            params,
            &keys.1,
            SingleVerifier::new(params),
            &instances,
            &mut transcript,
        )
        .is_ok())
    }
}
