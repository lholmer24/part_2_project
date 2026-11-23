//! STARK acceptance and rejection tests.

use circuits::stark::{
    self, build_trace, hash_check_row, hash_column_row, proof_options, trace_length, trace_width,
    MimcAir, MimcPreimageCircuit, MimcPublicInputs, FOURTH_COLUMN, HASH_COLUMN, PREIMAGE_COLUMN,
    SQUARE_COLUMN, STATE_COLUMN,
};
use mimc::{MimcParams, Statement, MAX_ROUNDS};
use winterfell::math::fields::f128::BaseElement;
use winterfell::math::FieldElement;
use winterfell::{Air, EvaluationFrame, Proof, Trace, TraceInfo};

const PREIMAGE: u64 = 12345;

fn statement(rounds: usize) -> (MimcParams<BaseElement>, BaseElement) {
    let params = MimcParams::<BaseElement>::load(rounds, 5).expect("load MiMC params");
    let hash = mimc::hash(&params, BaseElement::from(PREIMAGE));
    (params, hash)
}

/// `preimage` is `None` only when the witness is deliberately absent.
fn circuit(
    params: &MimcParams<BaseElement>,
    hash: BaseElement,
    preimage: Option<BaseElement>,
) -> MimcPreimageCircuit {
    MimcPreimageCircuit {
        statement: Statement {
            params: params.clone(),
            hash,
            preimage,
        },
    }
}

fn build(rounds: usize) -> (MimcParams<BaseElement>, BaseElement, Proof) {
    let (params, hash) = statement(rounds);
    let proof = stark::prove(
        &circuit(&params, hash, Some(BaseElement::from(PREIMAGE))),
        proof_options(),
    )
    .expect("prove");

    (params, hash, proof)
}

fn verify(hash: BaseElement, params: &MimcParams<BaseElement>, proof: Proof) -> bool {
    stark::verify(proof, &MimcPublicInputs::new(hash, params.clone())).is_ok()
}

#[test]
fn accepts_valid_proof() {
    for rounds in [1usize, 2, 4, 8, 16] {
        let (params, hash, proof) = build(rounds);
        assert!(verify(hash, &params, proof), "rounds = {rounds}");
    }
}

#[test]
#[cfg_attr(
    not(feature = "extended-tests"),
    ignore = "extended: run with --features extended-tests"
)]
fn accepts_valid_proof_at_every_round_count() {
    for k in 0..=MAX_ROUNDS.trailing_zeros() {
        let rounds = 1usize << k;
        let (params, hash, proof) = build(rounds);

        assert!(verify(hash, &params, proof), "rounds = {rounds}");
    }
}

#[test]
fn rejects_proof_for_wrong_public_hash() {
    let rounds = 8;
    let (params, hash, proof) = build(rounds);
    let wrong_hash = hash + BaseElement::from(1u64);

    assert!(!verify(wrong_hash, &params, proof));
}

#[test]
fn rejects_tampered_proof() {
    let rounds = 8;
    let (params, hash, proof) = build(rounds);
    let mut bytes = proof.to_bytes();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;

    // A byte flip that breaks the encoding is also a rejection.
    if let Ok(altered) = Proof::from_bytes(&bytes) {
        assert!(!verify(hash, &params, altered));
    }
}

#[test]
fn trace_matches_reference_chain() {
    for rounds in [1usize, 2, 4, 8, 16] {
        let (params, hash) = statement(rounds);
        let x = BaseElement::from(PREIMAGE);
        let trace = build_trace(&circuit(&params, hash, Some(x)));
        let length = trace_length(rounds);

        assert_eq!(trace.length(), length, "rounds = {rounds}");

        // The preimage column is constant in every row, including padding.
        for row in 0..length {
            assert_eq!(
                trace.get(PREIMAGE_COLUMN, row),
                x,
                "rounds = {rounds}, row = {row}"
            );
        }

        let mut state = x;
        for row in 0..rounds {
            assert_eq!(trace.get(STATE_COLUMN, row), state, "rounds = {rounds}");

            let sum = state + params.round_constants[row];
            let square = sum.exp(2u32.into());
            assert_eq!(
                trace.get(SQUARE_COLUMN, row),
                square,
                "rounds = {rounds}, row = {row}"
            );
            assert_eq!(
                trace.get(FOURTH_COLUMN, row),
                square.exp(2u32.into()),
                "rounds = {rounds}, row = {row}"
            );

            state = square.exp(2u32.into()) * sum;
        }

        // The hash is held only at its row.
        assert_eq!(trace.get(HASH_COLUMN, hash_column_row(rounds)), hash);
        for row in 0..length {
            if row != hash_column_row(rounds) {
                assert_eq!(trace.get(HASH_COLUMN, row), BaseElement::ZERO);
            }
        }

        // Padding rows are zero.
        for row in rounds..length {
            for column in [STATE_COLUMN, SQUARE_COLUMN, FOURTH_COLUMN, HASH_COLUMN] {
                assert_eq!(
                    trace.get(column, row),
                    BaseElement::ZERO,
                    "column = {column}, row = {row}, rounds = {rounds}"
                );
            }
        }
    }
}

#[test]
fn periodic_columns_match_layout() {
    for rounds in [1usize, 2, 4, 8, 16] {
        let (params, hash) = statement(rounds);
        let n = trace_length(rounds);
        let air = <MimcAir as Air>::new(
            TraceInfo::new(trace_width(), n),
            MimcPublicInputs::new(hash, params.clone()),
            proof_options(),
        );

        let columns = air.get_periodic_column_values();
        assert_eq!(columns.len(), 5, "rounds = {rounds}");

        for column in &columns {
            assert_eq!(column.len(), n, "rounds = {rounds}");
        }

        let constants = &columns[0];
        let next_constants = &columns[1];
        let first_row = &columns[2];
        let chain = &columns[3];
        let last = &columns[4];

        for i in 0..n {
            let expected_constant = if i < rounds {
                params.round_constants[i]
            } else {
                BaseElement::ZERO
            };
            assert_eq!(constants[i], expected_constant, "C[{i}], rounds = {rounds}");

            let expected_next = if i < rounds - 1 {
                params.round_constants[i + 1]
            } else {
                BaseElement::ZERO
            };
            assert_eq!(
                next_constants[i], expected_next,
                "Cnext[{i}], rounds = {rounds}"
            );

            let expected_first = if i == 0 {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };
            assert_eq!(first_row[i], expected_first, "F[{i}], rounds = {rounds}");

            let expected_chain = if i + 1 < rounds {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };
            assert_eq!(chain[i], expected_chain, "A[{i}], rounds = {rounds}");

            let expected_last = if i == hash_check_row(rounds) {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };
            assert_eq!(last[i], expected_last, "L[{i}], rounds = {rounds}");
        }
    }
}

#[test]
fn constraint_degree_sets_the_composition_domain() {
    // Declaring degree 3 keeps the constraint evaluation domain at `2n` and
    // the composition polynomial at two columns; degree 6 would give `8n` and
    // five columns.
    for rounds in [1usize, 2, 8, 16, 64] {
        let (params, hash) = statement(rounds);
        let n = trace_length(rounds);
        let air = <MimcAir as Air>::new(
            TraceInfo::new(trace_width(), n),
            MimcPublicInputs::new(hash, params),
            proof_options(),
        );

        assert_eq!(air.trace_length(), n, "rounds = {rounds}");
        assert_eq!(air.context().ce_domain_size(), 2 * n, "rounds = {rounds}");
        assert_eq!(
            air.context().num_constraint_composition_columns(),
            2,
            "rounds = {rounds}"
        );
    }
}

#[test]
fn final_round_intermediates_are_constrained() {
    // Winterfell exempts the last row, so the final round must be checked
    // from row `r - 2`; this fails if those checks are dropped.
    for rounds in [2usize, 8, 16] {
        let (params, hash) = statement(rounds);
        let circuit = circuit(&params, hash, Some(BaseElement::from(PREIMAGE)));
        let trace = build_trace(&circuit);
        let n = trace_length(rounds);
        let air = <MimcAir as Air>::new(
            TraceInfo::new(trace_width(), n),
            MimcPublicInputs::new(hash, params),
            proof_options(),
        );

        let row = hash_check_row(rounds);
        let current: Vec<BaseElement> = (0..trace_width())
            .map(|column| trace.get(column, row))
            .collect();
        let next: Vec<BaseElement> = (0..trace_width())
            .map(|column| trace.get(column, row + 1))
            .collect();
        let periodic: Vec<BaseElement> = air
            .get_periodic_column_values()
            .iter()
            .map(|column| column[row])
            .collect();

        let evaluate = |frame: &EvaluationFrame<BaseElement>| {
            let mut result = vec![BaseElement::ZERO; air.context().num_transition_constraints()];
            air.evaluate_transition(frame, &periodic, &mut result);
            result
        };

        let honest = evaluate(&EvaluationFrame::from_rows(current.clone(), next.clone()));
        assert!(
            honest.iter().all(|value| *value == BaseElement::ZERO),
            "rounds = {rounds}: {honest:?}"
        );

        for column in [SQUARE_COLUMN, FOURTH_COLUMN] {
            let mut corrupted = next.clone();
            corrupted[column] += BaseElement::ONE;
            let result = evaluate(&EvaluationFrame::from_rows(current.clone(), corrupted));
            assert!(
                result.iter().any(|value| *value != BaseElement::ZERO),
                "column {column} is not constrained at row {row}, rounds = {rounds}"
            );
        }
    }
}
