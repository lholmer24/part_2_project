//! Spartan adapter for the benchmark harness.
//!
//! The adapter calls the `spartan` SNARK API directly. It holds no timer, so
//! the harness times setup, proving and verification at one call boundary. The
//! R1CS builder is in `circuits::spartan`.
//!
//! Spartan is transparent. Its generators are tied to one instance shape:
//! `MultiCommitGens::commit` asserts `gens_n.n == scalars.len()`, so a
//! max-size generator set cannot serve a smaller instance. The adapter caches
//! one `SNARKGens` per measured round count. Building a set is untimed, like
//! universal parameter generation for the other systems.
//!
//! The timed setup is the deterministic preprocessing: the adapter builds the
//! R1CS matrices and calls `SNARK::encode`. Proving builds the witness
//! assignment and calls `SNARK::prove`.
//!
//! `SNARKGens::new` pads `num_vars` itself but not `num_cons`. The adapter
//! therefore passes `R1CSShape::padded_num_cons`.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use circuits::spartan::{build_assignments, build_inputs, build_shape, Assignments};
use curve25519_dalek_v4::scalar::Scalar;
use merlin_v3::Transcript;
use mimc::field_names::RISTRETTO255_SCALAR;
use mimc::MimcParams;
use spartan_lib::{ComputationCommitment, ComputationDecommitment, Instance, SNARKGens, SNARK};

use crate::{benchmark_seed, BoxError, ProofBox, System};

/// Domain-separation label for the proof transcript.
const DOMAIN: &[u8] = b"mimc-spartan-v1";

/// Build one `SNARKGens` set from a measured circuit shape.
fn generators(mimc: &MimcParams<Scalar>) -> Result<SNARKGens, BoxError> {
    let shape = build_shape(mimc).map_err(|error| -> BoxError { Box::new(error) })?;
    Ok(SNARKGens::new(
        shape.padded_num_cons(),
        shape.num_vars,
        shape.num_inputs,
        shape.max_nonzeros(),
    ))
}

struct Prepared {
    mimc: MimcParams<Scalar>,
    hash: Scalar,
    preimage: Scalar,
}

/// The encoded computation and the matrices it commits to.
struct SpartanSetup {
    instance: Instance,
    commitment: ComputationCommitment,
    decommitment: ComputationDecommitment,
}

/// A Spartan proof.
struct SpartanProof {
    proof: SNARK,
}

/// Harness adapter for Spartan over Ristretto255.
#[derive(Default)]
pub struct SpartanSystem {
    /// One generator set per round count, because Spartan fixes it per shape.
    gens: BTreeMap<usize, SNARKGens>,
    prepared: Option<Prepared>,
    setup: Option<SpartanSetup>,
}

impl SpartanSystem {
    /// Create an adapter with no prepared state.
    pub fn new() -> Self {
        Self::default()
    }
}

impl System for SpartanSystem {
    fn name(&self) -> &str {
        "spartan"
    }

    fn field(&self) -> &str {
        RISTRETTO255_SCALAR
    }

    fn prepare_universal(&mut self, max_rounds: usize) -> Result<(), BoxError> {
        // Build the largest set now. `prepare` adds any smaller set that the
        // sweep needs.
        let mimc = MimcParams::<Scalar>::load(max_rounds, 5)
            .map_err(|error| -> BoxError { Box::new(error) })?;
        self.gens.insert(max_rounds, generators(&mimc)?);
        Ok(())
    }

    fn prepare(&mut self, rounds: usize) -> Result<(), BoxError> {
        let mimc = MimcParams::<Scalar>::load(rounds, 5)
            .map_err(|error| -> BoxError { Box::new(error) })?;

        if let Entry::Vacant(entry) = self.gens.entry(rounds) {
            entry.insert(generators(&mimc)?);
        }

        let preimage = mimc::uniform_from_seed::<Scalar>(&benchmark_seed(rounds, 0));
        let hash = mimc::hash(&mimc, preimage);

        self.prepared = Some(Prepared {
            mimc,
            hash,
            preimage,
        });
        self.setup = None;
        Ok(())
    }

    fn prepare_instance(&mut self, rounds: usize, instance: usize) -> Result<(), BoxError> {
        let prepared = match &mut self.prepared {
            Some(prepared) => prepared,
            None => return Err("spartan prepare was not run".into()),
        };
        let preimage = mimc::uniform_from_seed::<Scalar>(&benchmark_seed(rounds, instance));
        prepared.hash = mimc::hash(&prepared.mimc, preimage);
        prepared.preimage = preimage;
        Ok(())
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("spartan prepare was not run".into()),
        };
        let gens = self
            .gens
            .get(&prepared.mimc.rounds)
            .ok_or("spartan generators were not built")?;

        let shape = build_shape(&prepared.mimc).map_err(|error| -> BoxError { Box::new(error) })?;
        let instance = shape
            .instance()
            .map_err(|error| -> BoxError { Box::new(error) })?;
        let (commitment, decommitment) = SNARK::encode(&instance, gens);

        self.setup = Some(SpartanSetup {
            instance,
            commitment,
            decommitment,
        });
        Ok(())
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("spartan prepare was not run".into()),
        };
        let gens = self
            .gens
            .get(&prepared.mimc.rounds)
            .ok_or("spartan generators were not built")?;
        let setup = match &self.setup {
            Some(setup) => setup,
            None => return Err("spartan setup was not run".into()),
        };

        let Assignments { vars, inputs } =
            build_assignments(&prepared.mimc, prepared.hash, prepared.preimage)
                .map_err(|error| -> BoxError { Box::new(error) })?;

        let mut transcript = Transcript::new(DOMAIN);
        transcript.append_u64(b"rounds", prepared.mimc.rounds as u64);
        let proof = SNARK::prove(
            &setup.instance,
            &setup.commitment,
            &setup.decommitment,
            vars,
            &inputs,
            gens,
            &mut transcript,
        );

        Ok(ProofBox::new(SpartanProof { proof }))
    }

    fn proof_size(&self, proof: &ProofBox) -> Result<usize, BoxError> {
        let proof = proof
            .downcast_ref::<SpartanProof>()
            .ok_or("spartan proof type mismatch")?;
        let bytes = bincode::serialize(&proof.proof)
            .map_err(|error| -> BoxError { format!("spartan serialisation: {error}").into() })?;
        Ok(bytes.len())
    }

    fn verify(&self, proof: &ProofBox) -> Result<bool, BoxError> {
        let prepared = match &self.prepared {
            Some(prepared) => prepared,
            None => return Err("spartan prepare was not run".into()),
        };
        let gens = self
            .gens
            .get(&prepared.mimc.rounds)
            .ok_or("spartan generators were not built")?;
        let setup = match &self.setup {
            Some(setup) => setup,
            None => return Err("spartan setup was not run".into()),
        };
        let proof = proof
            .downcast_ref::<SpartanProof>()
            .ok_or("spartan proof type mismatch")?;

        // The verifier needs the public hash, not the preimage.
        let inputs =
            build_inputs(prepared.hash).map_err(|error| -> BoxError { Box::new(error) })?;

        let mut transcript = Transcript::new(DOMAIN);
        transcript.append_u64(b"rounds", prepared.mimc.rounds as u64);

        Ok(proof
            .proof
            .verify(&setup.commitment, &inputs, &mut transcript, gens)
            .is_ok())
    }
}
