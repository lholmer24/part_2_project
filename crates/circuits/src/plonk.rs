//! PLONK MiMC preimage circuit.
//!
//! One round `s -> (s + c)^5` is three degree-two gates on the 2-4-5 chain:
//!
//! ```text
//! t2 = s^2 + 2c·s + c^2 = (s + c)^2
//! t4 = t2^2
//! s' = t4·s + c·t4 = t4·(s + c)
//! ```
//!
//! Folding `+ c` into gates 1 and 3 avoids a witness for `s + c`. Reusing a
//! witness between gates is the copy constraint. The finish gate enforces
//! `state + x - h = 0`, so the layout uses `3r + 6` rows.

use dusk_plonk::prelude::{BlsScalar, Circuit, Composer, Constraint, Error, Witness};
use mimc::{MimcParams, Statement};

pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<BlsScalar>;

pub const GATES_PER_ROUND: usize = 3;

pub const BASE_GATES: usize = 2;

pub const INITIAL_GATES: usize = 4;

/// Test oracle for the layout; universal parameters are sized from
/// [`circuit_size`] instead.
pub fn gate_count(rounds: usize) -> usize {
    INITIAL_GATES + GATES_PER_ROUND * rounds + BASE_GATES
}

/// Measured gate count for `params`. The circuit is synthesised without a
/// preimage, which is enough to size the universal parameters.
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

        // The layout fixes the 2-4-5 chain, so it only encodes e = 5.
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
