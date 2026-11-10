//! The MiMC preimage statement as a PLONK circuit.
//!
//! # Gate model
//!
//! `dusk-plonk` 0.24 is a turbo-PLONK composer. One row has four advice wires
//! `a`, `b`, `c`, `d` and the arithmetic gate
//!
//! ```text
//! q_M · a · b + q_L · a + q_R · b + q_O · c + q_F · d + q_C + PI = 0
//! ```
//!
//! where `q_M`, `q_L`, `q_R`, `q_O`, `q_F` and `q_C` are selectors on that row
//! and `PI` is the public-input value on that row. The gate is degree two, so
//! every other operation must be decomposed into rows of this shape.
//!
//! The public API exposes this gate through [`Composer::append_gate`],
//! [`Composer::gate_add`], [`Composer::gate_mul`] and
//! [`Composer::append_evaluated_output`]. Custom higher-degree selectors are
//! crate-private in this version and are not available to a circuit.
//!
//! # MiMC round layout
//!
//! The project fixes the round exponent to `e = 5`. `(s + c)^5` has
//! multiplicative depth three, so one round needs three degree-two gates:
//!
//! ```text
//! gate 1: t2 = (s + c)^2 = s^2 + 2c·s + c^2
//! gate 2: t4 = t2^2
//! gate 3: s' = t4·s + c·t4 = t4·(s + c)
//! ```
//!
//! The addition by `c` is folded into gate 1: use `a = b = s`, `q_M = 1`,
//! `q_L = 2c`, `q_C = c^2` and `q_O = -1` on `t2`. It is folded again into
//! gate 3: use `a = t4`, `b = s`, `q_M = 1`, `q_L = c` and `q_O = -1`. No
//! separate witness for `s + c` is needed. Gate 3 must not multiply `t4` by
//! `t2`, because that gives `(s + c)^6`.
//!
//! A [`Witness`] is a handle, not a value slot. Reusing the same handle in two
//! gates is how this circuit expresses a copy constraint: the composer's
//! permutation argument ties the two positions together. Circuit code does not
//! build the permutation columns itself.
//!
//! # Gate count
//!
//! Let `r` be the number of rounds.
//!
//! ```text
//! 3r       round gates
//!  1       final gate: state + x - h = 0
//!  1       public-input gate binding h
//!  4       rows added by Composer::initialized before circuit()
//! ```
//!
//! [`gate_count`] is the single source of truth for the size that
//! `PublicParameters` and the compiler must cover.
//!
//! # Witness values during setup
//!
//! The compiler runs [`Circuit::circuit`] to learn the gate shape, so
//! `preimage` is `None` during setup. Allocate a placeholder value for the
//! witness in that case: only the shape and the selectors matter, not the
//! values. The prover re-runs the same body with the real preimage and must
//! produce the same number of gates.

use dusk_plonk::prelude::{BlsScalar, Circuit, Composer, Constraint, Error, Witness};

/// PLONK circuit for the MiMC preimage statement.
///
/// The shared circuit type is aliased with the PLONK field.
pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<BlsScalar>;

/// Arithmetic gates one MiMC round costs in this layout.
pub const GATES_PER_ROUND: usize = 3;

/// Arithmetic gates outside the round loop: the public hash and the final
/// equality.
pub const BASE_GATES: usize = 2;

/// Rows that [`Composer::initialized`] appends before [`Circuit::circuit`]
/// runs.
pub const INITIAL_GATES: usize = 4;

/// Total arithmetic gates for `rounds` MiMC rounds.
///
/// This is the value that sizes the universal parameters and that the gate
/// count test asserts against `Composer::constraints()`.
pub fn gate_count(rounds: usize) -> usize {
    INITIAL_GATES + GATES_PER_ROUND * rounds + BASE_GATES
}

/// Append the three gates of one MiMC round and return the new state.
///
/// `state` is the handle holding `s`. The returned handle holds
/// `(s + c)^5`.
fn append_round(composer: &mut Composer, state: Witness, constant: BlsScalar) -> Witness {
    let t2 = composer.gate_add(
        Constraint::new()
            .mult(1)
            .left(constant.double())
            .constant(constant * constant)
            .a(state)
            .b(state),
    );

    let t4 = composer.gate_mul(Constraint::new().mult(1).a(t2).b(t2));

    composer.gate_mul(Constraint::new().mult(1).left(constant).a(t4).b(state))
}

impl Circuit for MimcPreimageCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let params = &self.statement.params;
        let hash = &self.statement.hash;
        let preimage = &self.statement.preimage;

        // This layout hardcodes the 2-4-5 addition chain, so it only encodes
        // the project's fixed exponent.
        debug_assert_eq!(params.exponent, 5, "PLONK layout fixes e = 5");

        let x = composer.append_witness(preimage.unwrap_or(BlsScalar::zero()));

        let mut state = x;

        for constant in params.round_constants.iter() {
            state = append_round(composer, state, *constant);
        }

        let public = composer.append_public(*hash);
        composer.append_gate(
            Constraint::new()
                .left(1)
                .right(1)
                .a(state)
                .b(x)
                .c(public)
                .output(-BlsScalar::one()),
        );
        Ok(())
    }
}
