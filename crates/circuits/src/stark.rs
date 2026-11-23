//! The MiMC preimage statement as a winterfell AIR and trace.
//!
//! The circuit has one public hash, `h`, and the private witness `x`. It
//! enforces `h = E(x) + x` over the parameters' rounds.
//!
//! # Layout
//!
//! The main trace has three columns: the MiMC state, the carried preimage and
//! the final hash candidate. Rows `0 .. rounds - 1` hold the pre-round states.
//! The trace length is `max(rounds, 8)`, so short traces are padded to the
//! winterfell minimum without adding an output row.
//!
//! Five periodic columns supply the round constants and the selectors for the
//! first row, the normal rounds and the final hash check. The hash is bound by
//! a transition constraint on the row before the last real state, and a
//! boundary assertion pins that hash to the public input.
//!
//! [`MimcPublicInputs`] carries the round count next to the hash, so the
//! verifier can recover `r` and load the shared round constants without reading
//! trace metadata.

use mimc::MimcParams;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions,
    Prover, ProverError, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree, VerifierError,
};

/// Minimum conjectured security that the verifier accepts, in bits.
pub const MIN_CONJECTURED_SECURITY_BITS: u32 = 100;

/// Public inputs for the MiMC preimage statement.
///
/// The hash is the statement output. The round count is a public parameter and
/// lets the AIR reconstruct the round constants during verification.
#[derive(Clone, Debug)]
pub struct MimcPublicInputs {
    /// Public hash, h.
    pub hash: BaseElement,
    /// Number of MiMC rounds, r.
    pub rounds: usize,
}

impl MimcPublicInputs {
    /// Build the public inputs for one statement.
    pub fn new(hash: BaseElement, rounds: usize) -> Self {
        Self { hash, rounds }
    }
}

impl ToElements<BaseElement> for MimcPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.hash, BaseElement::from(self.rounds as u64)]
    }
}

/// Column holding the MiMC state.
pub const STATE_COLUMN: usize = 0;

/// Column holding the carried preimage `x`.
pub const PREIMAGE_COLUMN: usize = 1;

/// Column holding the final hash candidate `h`.
pub const HASH_COLUMN: usize = 2;

/// Number of columns in the execution trace.
///
/// The trace has the state, the carried preimage and the hash candidate.
/// The AIR and [`build_trace`] must both use this width.
pub fn trace_width() -> usize {
    3
}

/// Number of rows in the execution trace for `rounds` MiMC rounds.
///
/// Rows `0 .. rounds - 1` hold the pre-round states. Short traces are padded
/// to the winterfell minimum of eight rows, so no extra output row is needed.
pub fn trace_length(rounds: usize) -> usize {
    debug_assert!(
        rounds.is_power_of_two(),
        "round count must be a power of two"
    );
    rounds.max(8)
}

/// AIR for the MiMC preimage statement.
pub struct MimcAir {
    context: AirContext<BaseElement>,
    public_inputs: MimcPublicInputs,
    params: MimcParams<BaseElement>,
}

impl MimcAir {
    /// The public inputs this AIR instance was built with.
    pub fn public_inputs(&self) -> &MimcPublicInputs {
        &self.public_inputs
    }

    /// The MiMC parameters loaded for this AIR instance.
    pub fn params(&self) -> &MimcParams<BaseElement> {
        &self.params
    }
}

impl Air for MimcAir {
    type BaseField = BaseElement;
    type PublicInputs = MimcPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let r = pub_inputs.rounds;
        assert_eq!(trace_info.width(), trace_width());
        assert_eq!(trace_info.length(), trace_length(pub_inputs.rounds));

        let params =
            MimcParams::<BaseElement>::load(pub_inputs.rounds, 5).expect("load MiMC params");

        let trace_len = trace_info.length();
        let round_degree = if r == 1 {
            TransitionConstraintDegree::new(1)
        } else {
            TransitionConstraintDegree::with_cycles(5, vec![trace_len])
        };
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::with_cycles(1, vec![trace_len]),
            round_degree,
            TransitionConstraintDegree::with_cycles(5, vec![trace_len]),
        ];
        let context = AirContext::new(trace_info, degrees, 1, options);

        Self {
            context,
            public_inputs: pub_inputs,
            params,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> {
        let n = self.trace_length();
        let r = self.params.rounds;

        let padded_constant = |index: usize| {
            self.params
                .round_constants
                .get(index)
                .copied()
                .unwrap_or(BaseElement::ZERO)
        };
        let select = |condition: bool| {
            if condition {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            }
        };
        let hash_row = if r == 1 { 0 } else { r - 2 };

        let constants = (0..n).map(&padded_constant).collect();
        let next_constants = (0..n).map(|i| padded_constant(i + 1)).collect();
        let first_row = (0..n).map(|i| select(i == 0)).collect();
        let active_round = (0..n).map(|i| select(i + 1 < r)).collect();
        let active_hash = (0..n).map(|i| select(i == hash_row)).collect();

        vec![
            constants,
            next_constants,
            first_row,
            active_round,
            active_hash,
        ]
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let r = self.params.rounds;

        result[0] = frame.next()[PREIMAGE_COLUMN] - frame.current()[PREIMAGE_COLUMN];
        result[1] =
            periodic_values[2] * (frame.current()[STATE_COLUMN] - frame.current()[PREIMAGE_COLUMN]);

        result[2] = periodic_values[3]
            * (frame.next()[STATE_COLUMN]
                - (frame.current()[STATE_COLUMN] + periodic_values[0]).exp(5u32.into()));

        let (state, constant, preimage, hash) = if r >= 2 {
            (
                frame.next()[STATE_COLUMN],
                periodic_values[1],
                frame.next()[PREIMAGE_COLUMN],
                frame.next()[HASH_COLUMN],
            )
        } else {
            (
                frame.current()[STATE_COLUMN],
                periodic_values[0],
                frame.current()[PREIMAGE_COLUMN],
                frame.current()[HASH_COLUMN],
            )
        };
        result[3] = periodic_values[4] * (hash - ((state + constant).exp(5u32.into()) + preimage));
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![Assertion::single(
            HASH_COLUMN,
            self.public_inputs.rounds - 1,
            self.public_inputs.hash,
        )]
    }
}

/// STARK circuit for the MiMC preimage statement.
///
/// The shared circuit type is aliased with the winterfell field.
pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<BaseElement>;

/// Build the execution trace for one MiMC statement.
///
/// The adapter calls this inside the timed `prove` call. The trace records the
/// pre-round states, carries the preimage and writes the public hash candidate
/// at the last real row.
pub fn build_trace(circuit: &MimcPreimageCircuit) -> TraceTable<BaseElement> {
    let width = trace_width();
    let rounds = circuit.statement.params.rounds;
    let length = trace_length(rounds);

    let x = circuit.statement.preimage.expect("missing MiMC preimage");
    let h = circuit.statement.hash;
    let params = &circuit.statement.params;
    let initial_hash = if rounds == 1 { h } else { BaseElement::ZERO };

    let mut trace = TraceTable::new(width, length);

    trace.fill(
        |state| {
            state[STATE_COLUMN] = x;
            state[PREIMAGE_COLUMN] = x;
            state[HASH_COLUMN] = initial_hash;
        },
        |step, state| {
            let next_row = step + 1;
            let in_round = next_row < rounds;
            let is_hash_row = next_row == rounds - 1;

            let curr_state = state[STATE_COLUMN];
            state[STATE_COLUMN] = if in_round {
                (curr_state + params.round_constants[step]).exp(params.exponent as u128)
            } else {
                BaseElement::ZERO
            };
            state[PREIMAGE_COLUMN] = x;
            state[HASH_COLUMN] = if is_hash_row { h } else { BaseElement::ZERO };
        },
    );
    trace
}

/// Grinding factor for the STARK benchmarks.
///
/// The project fixes this at 0. Grinding adds proof-of-work to the prover and
/// a variable nonce search to every sample. Winterfell adds the grinding bits
/// to the conjectured security only up to the `f128` modulus, and 42 queries
/// already reach that ceiling within 2 bits. Grinding 16 therefore cost a
/// search of about 2^16 hashes per proof and added no estimated security.
pub const GRINDING_FACTOR: u32 = 0;

/// Proof options for every STARK benchmark.
///
/// The parameters are 42 queries, blowup factor 8, [`GRINDING_FACTOR`], no
/// field extension and Blake3-256. Winterfell computes the conjectured
/// security as `min(min(128, 3 * 42 + 0) - 1, 128) = 125` bits, which is above
/// the verifier's 100-bit floor. Grinding cannot raise this estimate, because
/// the 128-bit `f128` modulus clamps it at 127 bits.
pub fn proof_options() -> ProofOptions {
    ProofOptions::new(
        42,
        8,
        GRINDING_FACTOR,
        FieldExtension::None,
        4,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Winterfell prover for [`MimcAir`].
///
/// The prover carries the public inputs so that they do not have to be read
/// back from the trace layout.
pub struct MimcProver {
    options: ProofOptions,
    public_inputs: MimcPublicInputs,
}

impl MimcProver {
    /// Build a prover with fixed options and public inputs.
    pub fn new(options: ProofOptions, public_inputs: MimcPublicInputs) -> Self {
        Self {
            options,
            public_inputs,
        }
    }
}

impl Prover for MimcProver {
    type BaseField = BaseElement;
    type Air = MimcAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> MimcPublicInputs {
        self.public_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Prove one MiMC statement.
///
/// Trace generation and proof generation both happen here, so the harness
/// times them inside its `prove` phase.
pub fn prove(circuit: &MimcPreimageCircuit, options: ProofOptions) -> Result<Proof, ProverError> {
    let public_inputs =
        MimcPublicInputs::new(circuit.statement.hash, circuit.statement.params.rounds);
    let trace = build_trace(circuit);
    MimcProver::new(options, public_inputs).prove(trace)
}

/// Verify one MiMC proof against the public inputs.
pub fn verify(proof: Proof, public_inputs: &MimcPublicInputs) -> Result<(), VerifierError> {
    winterfell::verify::<
        MimcAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(
        proof,
        public_inputs.clone(),
        &AcceptableOptions::MinConjecturedSecurity(MIN_CONJECTURED_SECURITY_BITS),
    )
}
