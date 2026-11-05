//! The MiMC preimage statement as a winterfell AIR and trace.
//!
//! Not done yet.

use mimc::MimcParams;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo, TraceTable,
};

/// Public inputs for the MiMC preimage statement.
#[derive(Clone, Debug)]
pub struct MimcPublicInputs {
    /// Public hash, h.
    pub hash: BaseElement,
}

impl ToElements<BaseElement> for MimcPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        todo!("STARK public input encoding is not done yet")
    }
}

/// AIR for the MiMC preimage statement.
#[allow(dead_code)]
pub struct MimcAir {
    context: AirContext<BaseElement>,
    public_inputs: MimcPublicInputs,
    options: ProofOptions,
}

impl Air for MimcAir {
    type BaseField = BaseElement;
    type PublicInputs = MimcPublicInputs;

    fn new(
        _trace_info: TraceInfo,
        _pub_inputs: Self::PublicInputs,
        _options: ProofOptions,
    ) -> Self {
        todo!("STARK AIR construction is not done yet")
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        todo!("STARK AIR context is not done yet")
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        _result: &mut [E],
    ) {
        todo!("STARK transition constraints are not done yet")
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        todo!("STARK assertions are not done yet")
    }
}

/// STARK circuit for the MiMC preimage statement.
#[derive(Clone, Debug)]
pub struct MimcPreimageCircuit {
    /// MiMC parameters shared by setup and proving.
    pub params: MimcParams<BaseElement>,
    /// Public hash, h.
    pub hash: BaseElement,
    /// Private preimage, x. `None` during setup.
    pub preimage: Option<BaseElement>,
}

/// Build the execution trace for one MiMC statement.
///
/// The adapter calls this inside the timed `prove` call. The body is left for
/// the implementation.
pub fn build_trace(_circuit: &MimcPreimageCircuit) -> TraceTable<BaseElement> {
    todo!("STARK trace generation is not done yet")
}
