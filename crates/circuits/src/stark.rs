//! Winterfell AIR and trace for the MiMC preimage statement.
//!
//! Five columns: `state`, `preimage`, `hash`, `square` and `fourth`. Row `i`
//! holds `s_i` for `i < r`, so `r` rounds use `r` rows.
//!
//! ```text
//! t2_i   = (s_i + c_i)^2
//! t4_i   = t2_i^2
//! s_i+1  = t4_i * (s_i + c_i)                    rows 0 .. r-2
//! h      = t4_{r-1} * (s_{r-1} + c_{r-1}) + x    checked at row r-2
//! ```
//!
//! Winterfell exempts the last transition, so no gate on row `r-1` is
//! enforced: the check sits on row `r-2` and reads the final round's
//! intermediates from `next`, together with `c_{r-1}` from the shifted
//! constant column. For `r = 1` it reads row 0 directly.
//!
//! A selector adds one degree, so each round constraint is degree 3: the
//! constraint evaluation domain is `2n` and the composition polynomial splits
//! into two columns instead of five.

use std::sync::Arc;

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

pub const MIN_CONJECTURED_SECURITY_BITS: u32 = 100;

/// The round parameters travel with the public inputs, so `Air::new` does no
/// file I/O during the timed prove and verify phases.
#[derive(Clone, Debug)]
pub struct MimcPublicInputs {
    pub hash: BaseElement,
    pub params: MimcParams<BaseElement>,
}

impl MimcPublicInputs {
    pub fn new(hash: BaseElement, params: MimcParams<BaseElement>) -> Self {
        Self { hash, params }
    }

    pub fn rounds(&self) -> usize {
        self.params.rounds
    }
}

impl ToElements<BaseElement> for MimcPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.hash, BaseElement::from(self.params.rounds as u64)]
    }
}

pub const STATE_COLUMN: usize = 0;

pub const PREIMAGE_COLUMN: usize = 1;

pub const HASH_COLUMN: usize = 2;

pub const SQUARE_COLUMN: usize = 3;

pub const FOURTH_COLUMN: usize = 4;

pub fn trace_width() -> usize {
    5
}

pub fn trace_length(rounds: usize) -> usize {
    debug_assert!(
        rounds.is_power_of_two(),
        "round count must be a power of two"
    );
    rounds.max(8)
}

/// Winterfell exempts the last transition, so for `r >= 2` the check sits on
/// row `r - 2` and reads the last round's intermediates from row `r - 1`.
pub fn hash_check_row(rounds: usize) -> usize {
    if rounds == 1 {
        0
    } else {
        rounds - 2
    }
}

/// Row carrying `h`: the assertion pins it here, while the check reads it
/// through `next` from [`hash_check_row`].
pub fn hash_column_row(rounds: usize) -> usize {
    rounds - 1
}

pub struct MimcAir {
    context: AirContext<BaseElement>,
    public_inputs: MimcPublicInputs,
}

impl MimcAir {
    pub fn public_inputs(&self) -> &MimcPublicInputs {
        &self.public_inputs
    }

    pub fn params(&self) -> &MimcParams<BaseElement> {
        &self.public_inputs.params
    }
}

impl Air for MimcAir {
    type BaseField = BaseElement;
    type PublicInputs = MimcPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), trace_width());
        assert_eq!(trace_info.length(), trace_length(pub_inputs.rounds()));

        let trace_len = trace_info.length();
        let round_degree = TransitionConstraintDegree::with_cycles(2, vec![trace_len]);
        // With one round the chain selector is empty, so those three
        // constraints are identically zero and must be declared at degree 1.
        let chain_degree = if pub_inputs.rounds() == 1 {
            TransitionConstraintDegree::new(1)
        } else {
            round_degree.clone()
        };
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::with_cycles(1, vec![trace_len]),
            chain_degree.clone(),
            chain_degree.clone(),
            chain_degree,
            round_degree.clone(),
            round_degree.clone(),
            round_degree,
        ];
        let context = AirContext::new(trace_info, degrees, 1, options);

        Self {
            context,
            public_inputs: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> {
        let n = self.trace_length();
        let rounds = self.params().rounds;

        let padded_constant = |index: usize| {
            self.params()
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
        let check_row = hash_check_row(rounds);

        let constants = (0..n).map(padded_constant).collect();
        let next_constants = (0..n).map(|i| padded_constant(i + 1)).collect();
        let first_row = (0..n).map(|i| select(i == 0)).collect();
        let chain = (0..n).map(|i| select(i + 1 < rounds)).collect();
        let last = (0..n).map(|i| select(i == check_row)).collect();

        vec![constants, next_constants, first_row, chain, last]
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let rounds = self.params().rounds;

        let current = periodic_values[0];
        let next_constant = periodic_values[1];
        let first_row = periodic_values[2];
        let chain = periodic_values[3];
        let last = periodic_values[4];

        let cur = frame.current();
        let next = frame.next();

        result[0] = next[PREIMAGE_COLUMN] - cur[PREIMAGE_COLUMN];
        result[1] = first_row * (cur[STATE_COLUMN] - cur[PREIMAGE_COLUMN]);
        result[2] = chain * (cur[SQUARE_COLUMN] - (cur[STATE_COLUMN] + current).exp(2u32.into()));
        result[3] = chain * (cur[FOURTH_COLUMN] - cur[SQUARE_COLUMN].exp(2u32.into()));
        result[4] =
            chain * (next[STATE_COLUMN] - cur[FOURTH_COLUMN] * (cur[STATE_COLUMN] + current));

        // The last transition is exempt: check the final round here from
        // `next`, then the hash from those checked cells.
        let (state, constant, square, fourth, hash) = if rounds >= 2 {
            (
                next[STATE_COLUMN],
                next_constant,
                next[SQUARE_COLUMN],
                next[FOURTH_COLUMN],
                next[HASH_COLUMN],
            )
        } else {
            (
                cur[STATE_COLUMN],
                current,
                cur[SQUARE_COLUMN],
                cur[FOURTH_COLUMN],
                cur[HASH_COLUMN],
            )
        };
        result[5] = last * (square - (state + constant).exp(2u32.into()));
        result[6] = last * (fourth - square.exp(2u32.into()));
        result[7] = last * (hash - (fourth * (state + constant) + cur[PREIMAGE_COLUMN]));
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![Assertion::single(
            HASH_COLUMN,
            hash_column_row(self.public_inputs.rounds()),
            self.public_inputs.hash,
        )]
    }
}

pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<BaseElement>;

pub fn build_trace(circuit: &MimcPreimageCircuit) -> TraceTable<BaseElement> {
    let width = trace_width();
    let rounds = circuit.statement.params.rounds;
    let length = trace_length(rounds);

    let x = circuit.statement.preimage.expect("missing MiMC preimage");
    let h = circuit.statement.hash;
    let constants: Arc<[BaseElement]> = circuit.statement.params.round_constants.clone();

    let mut trace = TraceTable::new(width, length);

    trace.fill(
        |state| {
            let sum = x + constants[0];
            state[STATE_COLUMN] = x;
            state[PREIMAGE_COLUMN] = x;
            state[HASH_COLUMN] = if rounds == 1 { h } else { BaseElement::ZERO };
            state[SQUARE_COLUMN] = sum.exp(2u32.into());
            state[FOURTH_COLUMN] = sum.exp(2u32.into()).exp(2u32.into());
        },
        |step, state| {
            let row = step + 1;
            if row < rounds {
                let sum = state[STATE_COLUMN] + constants[step];
                let next_state = sum.exp(2u32.into()).exp(2u32.into()) * sum;
                let next_sum = next_state + constants[row];
                state[STATE_COLUMN] = next_state;
                state[PREIMAGE_COLUMN] = x;
                state[HASH_COLUMN] = if row == rounds - 1 {
                    h
                } else {
                    BaseElement::ZERO
                };
                state[SQUARE_COLUMN] = next_sum.exp(2u32.into());
                state[FOURTH_COLUMN] = next_sum.exp(2u32.into()).exp(2u32.into());
            } else {
                state[STATE_COLUMN] = BaseElement::ZERO;
                state[PREIMAGE_COLUMN] = x;
                state[HASH_COLUMN] = BaseElement::ZERO;
                state[SQUARE_COLUMN] = BaseElement::ZERO;
                state[FOURTH_COLUMN] = BaseElement::ZERO;
            }
        },
    );
    trace
}

/// Grinding is 0: 42 queries already reach 125 bits, and the 128-bit `f128`
/// modulus clamps the estimate at 127 bits.
pub const GRINDING_FACTOR: u32 = 0;

/// 42 queries, blowup 8, no field extension: 125 conjectured bits.
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

pub struct MimcProver {
    options: ProofOptions,
    public_inputs: MimcPublicInputs,
}

impl MimcProver {
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

pub fn prove(circuit: &MimcPreimageCircuit, options: ProofOptions) -> Result<Proof, ProverError> {
    let public_inputs =
        MimcPublicInputs::new(circuit.statement.hash, circuit.statement.params.clone());
    let trace = build_trace(circuit);
    MimcProver::new(options, public_inputs).prove(trace)
}

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
