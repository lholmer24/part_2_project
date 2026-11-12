//! Bulletproofs adapter for the benchmark harness.
//!
//! The adapter calls the `bulletproofs` R1CS API directly. It holds no timer,
//! so the harness times proving and verification at one call boundary. The
//! circuit and the shared prover/verifier gadget are in
//! `circuits::bulletproofs`.
//!
//! Bulletproofs is transparent: the generators are built once in
//! [`System::prepare_universal`](crate::System::prepare_universal) and there is
//! no per-configuration setup phase.
//!
//! The public hash is committed with zero blinding, so the verifier can rebuild
//! the commitment from the hash. The preimage uses a fresh random blinding on
//! every proof.

use bulletproofs_lib::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs_lib::{BulletproofGens, PedersenGens};
use circuits::bulletproofs::{
    constrain_prover, constrain_verifier, multiplier_capacity, MimcCommitments, MimcPreimageCircuit,
};
use curve25519_dalek_v3::scalar::Scalar;
use merlin::Transcript;
use mimc::field_names::RISTRETTO255_SCALAR;
use mimc::{MimcParams, Statement};
use rand::thread_rng;

use crate::{BoxError, ProofBox, System};

/// Preimage used for every Bulletproofs benchmark statement.
const PREIMAGE: u64 = 12345;

/// Domain-separation label for the proof transcript.
const DOMAIN: &[u8] = b"mimc-bulletproofs-v1";

struct Prepared {
    mimc: MimcParams<Scalar>,
    hash: Scalar,
    preimage: Scalar,
}

/// A Bulletproofs proof plus the commitments that bind the statement.
struct BulletproofsProof {
    proof: R1CSProof,
    commitments: MimcCommitments,
}

/// Harness adapter for Bulletproofs over Ristretto255.
pub struct BulletproofsSystem {
    pc_gens: Option<PedersenGens>,
    bp_gens: Option<BulletproofGens>,
    prepared: Option<Prepared>,
}

impl BulletproofsSystem {
    /// Create an adapter with no prepared state.
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
        // `BulletproofGens` must cover the padded multiplier count of the
        // largest circuit in the sweep.
        self.pc_gens = Some(PedersenGens::default());
        self.bp_gens = Some(BulletproofGens::new(multiplier_capacity(max_rounds), 1));
        Ok(())
    }

    fn prepare(&mut self, rounds: usize) -> Result<(), BoxError> {
        let mimc = MimcParams::<Scalar>::load(rounds, 5)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let preimage = Scalar::from(PREIMAGE);
        let hash = mimc::hash(&mimc, preimage);

        self.prepared = Some(Prepared {
            mimc,
            hash,
            preimage,
        });
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
