//! Bulletproofs adapter.
//!
//! Transparent, so there is no per-configuration setup; the generators are
//! built once in `prepare_universal`.

use bulletproofs_lib::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs_lib::{BulletproofGens, PedersenGens};
use circuits::bulletproofs::{
    circuit_size, constrain_prover, constrain_verifier, generator_capacity, MimcCommitments,
    MimcPreimageCircuit,
};
use curve25519_dalek_v3::scalar::Scalar;
use merlin::Transcript;
use mimc::field_names::RISTRETTO255_SCALAR;
use mimc::{MimcParams, Statement};
use rand::thread_rng;

use crate::{benchmark_seed, BoxError, ProofBox, System};

const DOMAIN: &[u8] = b"mimc-bulletproofs-v1";

struct Prepared {
    mimc: MimcParams<Scalar>,
    hash: Scalar,
    preimage: Scalar,
}

struct BulletproofsProof {
    proof: R1CSProof,
    commitments: MimcCommitments,
}

pub struct BulletproofsSystem {
    pc_gens: Option<PedersenGens>,
    bp_gens: Option<BulletproofGens>,
    prepared: Option<Prepared>,
}

impl BulletproofsSystem {
    pub fn new() -> Self {
        Self {
            pc_gens: None,
            bp_gens: None,
            prepared: None,
        }
    }
}

impl Default for BulletproofsSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl System for BulletproofsSystem {
    fn name(&self) -> &str {
        "bulletproofs"
    }

    fn field(&self) -> &str {
        RISTRETTO255_SCALAR
    }

    fn prepare_universal(&mut self, max_rounds: usize) -> Result<(), BoxError> {
        // Size from a measured synthesis, not the multiplier formula.
        let mimc = MimcParams::<Scalar>::load(max_rounds, 5)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let size = circuit_size(&mimc).map_err(|error| -> BoxError { Box::new(error) })?;

        self.pc_gens = Some(PedersenGens::default());
        self.bp_gens = Some(BulletproofGens::new(
            generator_capacity(size.multipliers),
            1,
        ));
        Ok(())
    }

    fn prepare(&mut self, rounds: usize) -> Result<(), BoxError> {
        let mimc = MimcParams::<Scalar>::load(rounds, 5)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let preimage = mimc::uniform_from_seed::<Scalar>(&benchmark_seed(rounds, 0));
        let hash = mimc::hash(&mimc, preimage);

        self.prepared = Some(Prepared {
            mimc,
            hash,
            preimage,
        });
        Ok(())
    }

    fn prepare_instance(&mut self, rounds: usize, instance: usize) -> Result<(), BoxError> {
        let prepared = match &mut self.prepared {
            Some(prepared) => prepared,
            None => return Err("bulletproofs prepare was not run".into()),
        };
        let preimage = mimc::uniform_from_seed::<Scalar>(&benchmark_seed(rounds, instance));
        prepared.hash = mimc::hash(&prepared.mimc, preimage);
        prepared.preimage = preimage;
        Ok(())
    }

    fn has_setup(&self) -> bool {
        false
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        unreachable!("Bulletproofs has no setup phase")
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("bulletproofs prepare was not run".into()),
        };
        let pc_gens = match &self.pc_gens {
            Some(pc_gens) => pc_gens,
            None => return Err("bulletproofs generators were not built".into()),
        };
        let bp_gens = match &self.bp_gens {
            Some(bp_gens) => bp_gens,
            None => return Err("bulletproofs generators were not built".into()),
        };

        let circuit = MimcPreimageCircuit {
            statement: Statement {
                params: prepared.mimc.clone(),
                hash: prepared.hash,
                preimage: Some(prepared.preimage),
            },
        };

        let mut transcript = Transcript::new(DOMAIN);
        transcript.append_u64(b"rounds", prepared.mimc.rounds as u64);
        let mut prover = Prover::new(pc_gens, &mut transcript);

        let preimage_blinding = Scalar::random(&mut thread_rng());
        let commitments = constrain_prover(&mut prover, &circuit, preimage_blinding)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let proof = prover
            .prove(bp_gens)
            .map_err(|error| -> BoxError { Box::new(error) })?;

        Ok(ProofBox::new(BulletproofsProof { proof, commitments }))
    }

    fn proof_size(&self, proof: &ProofBox) -> Result<usize, BoxError> {
        let proof = proof
            .downcast_ref::<BulletproofsProof>()
            .ok_or("bulletproofs proof type mismatch")?;
        Ok(proof.proof.to_bytes().len())
    }

    fn verify(&self, proof: &ProofBox) -> Result<bool, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("bulletproofs prepare was not run".into()),
        };
        let pc_gens = match &self.pc_gens {
            Some(pc_gens) => pc_gens,
            None => return Err("bulletproofs generators were not built".into()),
        };
        let bp_gens = match &self.bp_gens {
            Some(bp_gens) => bp_gens,
            None => return Err("bulletproofs generators were not built".into()),
        };
        let proof = proof
            .downcast_ref::<BulletproofsProof>()
            .ok_or("bulletproofs proof type mismatch")?;

        let mut transcript = Transcript::new(DOMAIN);
        transcript.append_u64(b"rounds", prepared.mimc.rounds as u64);
        let mut verifier = Verifier::new(&mut transcript);

        // A commitment mismatch is a rejected statement, not an adapter failure.
        if constrain_verifier(
            pc_gens,
            &mut verifier,
            &prepared.mimc,
            prepared.hash,
            &proof.commitments,
        )
        .is_err()
        {
            return Ok(false);
        }

        Ok(verifier.verify(&proof.proof, pc_gens, bp_gens).is_ok())
    }
}
