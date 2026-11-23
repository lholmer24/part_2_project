//! STARK acceptance and rejection tests.

use circuits::stark::{
    self, build_trace, proof_options, trace_length, trace_width, MimcAir, MimcPreimageCircuit,
    MimcPublicInputs, HASH_COLUMN, PREIMAGE_COLUMN, STATE_COLUMN,
};
use mimc::{MimcParams, Statement, MAX_ROUNDS};
use winterfell::math::fields::f128::BaseElement;
use winterfell::math::FieldElement;
use winterfell::{Air, Proof, Trace, TraceInfo};

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

fn build(rounds: usize) -> (BaseElement, Proof) {
    let (params, hash) = statement(rounds);
    let proof = stark::prove(
        &circuit(&params, hash, Some(BaseElement::from(PREIMAGE))),
        proof_options(),
    )
    .expect("prove");

    (hash, proof)
}

fn verify(hash: BaseElement, rounds: usize, proof: Proof) -> bool {
    stark::verify(proof, &MimcPublicInputs::new(hash, rounds)).is_ok()
}

#[test]
fn accepts_valid_proof() {
    for rounds in [1usize, 2, 4, 8, 16] {
        let (hash, proof) = build(rounds);
        assert!(verify(hash, rounds, proof), "rounds = {rounds}");
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
        let (hash, proof) = build(rounds);

        assert!(verify(hash, rounds, proof), "rounds = {rounds}");
    }
}

#[test]
fn rejects_proof_for_wrong_public_hash() {
    let rounds = 8;
    let (hash, proof) = build(rounds);
    let wrong_hash = hash + BaseElement::from(1u64);

    assert!(!verify(wrong_hash, rounds, proof));
}

#[test]
fn rejects_tampered_proof() {
    let rounds = 8;
    let (hash, proof) = build(rounds);
    let mut bytes = proof.to_bytes();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;

    // A byte flip that breaks the encoding is also a rejection.
    if let Ok(altered) = Proof::from_bytes(&bytes) {
        assert!(!verify(hash, rounds, altered));
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

        // Row 0 holds the preimage.
        assert_eq!(trace.get(STATE_COLUMN, 0), x, "rounds = {rounds}");

        // Rows 1 .. rounds - 1 hold the pre-round states.
        let mut state = x;
        for row in 0..rounds - 1 {
            state = (state + params.round_constants[row]).exp(params.exponent as u128);
            assert_eq!(
                trace.get(STATE_COLUMN, row + 1),
                state,
                "rounds = {rounds}, row = {}",
                row + 1
            );
        }

        // The hash is held only at the last real row.
        assert_eq!(trace.get(HASH_COLUMN, rounds - 1), hash);

        // Padding rows and the remaining hash cells are zero.
        for row in rounds..length {
            assert_eq!(trace.get(STATE_COLUMN, row), BaseElement::ZERO);
        }
        for row in 0..length {
            if row != rounds - 1 {
                assert_eq!(trace.get(HASH_COLUMN, row), BaseElement::ZERO);
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
            MimcPublicInputs::new(hash, rounds),
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
        let active_round = &columns[3];
        let active_hash = &columns[4];

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

            let expected_active_round = if i < rounds - 1 {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };
            assert_eq!(
                active_round[i], expected_active_round,
                "A[{i}], rounds = {rounds}"
            );

            let hash_row = if rounds == 1 { 0 } else { rounds - 2 };
            let expected_active_hash = if i == hash_row {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };
            assert_eq!(
                active_hash[i], expected_active_hash,
                "L[{i}], rounds = {rounds}"
            );
        }
    }
}
