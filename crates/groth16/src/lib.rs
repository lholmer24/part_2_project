//! Groth16 proof of knowledge of a MiMC preimage over BLS12-381.

pub mod circuit;

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::rand::Rng;

pub use circuit::MimcPreimageCircuit;
pub use mimc::MimcParams;

/// The concrete Groth16 instantiation used by this crate.
pub type Groth16Bls12_381 = Groth16<Bls12_381>;

/// The circuit-specific common reference string and the verifying key.
pub struct Groth16Params {
    /// Proving key produced by the trusted setup.
    pub proving_key: ProvingKey<Bls12_381>,
    /// Verifying key produced by the trusted setup.
    pub verifying_key: VerifyingKey<Bls12_381>,
    /// Verifying key prepared for repeated verification.
    pub prepared_verifying_key: PreparedVerifyingKey<Bls12_381>,
}

/// Run the circuit-specific trusted setup for a fixed MiMC parameter set.
pub fn setup(params: MimcParams<Fr>, rng: &mut impl Rng) -> Result<Groth16Params, SynthesisError> {
    let circuit = MimcPreimageCircuit {
        params,
        hash: Fr::from(0u64),
        preimage: None,
    };
    let proving_key = Groth16Bls12_381::generate_random_parameters_with_reduction(circuit, rng)?;
    let verifying_key = proving_key.vk.clone();
    let prepared_verifying_key = prepare_verifying_key(&verifying_key);
    Ok(Groth16Params {
        proving_key,
        verifying_key,
        prepared_verifying_key,
    })
}

/// Create a proof for the given circuit instance.
pub fn prove(
    params: &Groth16Params,
    circuit: MimcPreimageCircuit,
    rng: &mut impl Rng,
) -> Result<Proof<Bls12_381>, SynthesisError> {
    Groth16Bls12_381::create_random_proof_with_reduction(circuit, &params.proving_key, rng)
}

/// Verify a proof against the public hash.
pub fn verify(
    params: &Groth16Params,
    public_hash: Fr,
    proof: &Proof<Bls12_381>,
) -> Result<bool, SynthesisError> {
    Groth16Bls12_381::verify_proof(&params.prepared_verifying_key, proof, &[public_hash])
}
