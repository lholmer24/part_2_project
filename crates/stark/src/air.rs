//! The MiMC preimage statement as a winterfell AIR.
//!
//! Not done yet.

use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
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
