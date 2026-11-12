//! The MiMC preimage statement as a PLONK circuit.
//!
//! One MiMC round `s -> (s + c)^5` is three arithmetic gates:
//!
//! ```text
//! gate 1: t2 = (s + c)^2 = s^2 + 2c·s + c^2
//! gate 2: t4 = t2^2
//! gate 3: s' = t4·s + c·t4 = t4·(s + c)
//! ```
//!
//! The `+ c` is folded into gate 1 and gate 3, so no separate witness for
//! `s + c` is needed. Reusing a witness handle between two gates is the copy
//! constraint between rounds. The final row enforces `state + x - h = 0`, with
//! `h` the public input and `x` the private preimage.
//!
//! The circuit uses `3r + 6` rows for `r` rounds, including the four rows that
//! `Composer::initialized` adds.

use dusk_plonk::prelude::{BlsScalar, Circuit, Composer, Constraint, Error, Witness};
use mimc::{MimcParams, Statement};

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

/// Expected arithmetic gate count for `rounds` MiMC rounds.
///
/// This is the test oracle for the layout. Universal parameters are sized from
/// [`circuit_size`] instead, so they cannot drift with this formula.
pub fn gate_count(rounds: usize) -> usize {
    INITIAL_GATES + GATES_PER_ROUND * rounds + BASE_GATES
}

/// Measure the arithmetic gate count for `params`.
///
/// The circuit is synthesised with a placeholder hash and no preimage. Only the
/// selectors and the row count matter here, so this is the size that the
/// universal parameters must cover.
pub fn circuit_size(params: &MimcParams<BlsScalar>) -> Result<usize, Error> {
    let circuit = MimcPreimageCircuit {
        statement: Statement {
            params: params.clone(),
            hash: BlsScalar::zero(),
            preimage: None,
        },
    };

    let mut composer = Composer::initialized();
    circuit.circuit(&mut composer)?;
    Ok(composer.constraints())
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

    let t4 = composer.gate_mul(Constraint::new()
        .mult(1)
        .a(t2)
        .b(t2)
    );

    composer.gate_mul(Constraint::new()
        .mult(1)
        .left(constant)
        .a(t4)
        .b(state)
    )
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
