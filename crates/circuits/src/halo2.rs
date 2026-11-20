//! The MiMC preimage statement as a Halo2 circuit.
//!
//! The circuit has one public hash, `h`, and the private witness `x`. It must
//! enforce `h = E(x) + x` over the parameters' rounds.
//!
//! # Layout
//!
//! The circuit uses two gates and one region:
//!
//! - `state` holds the chain: row 0 is the preimage, row `i + 1` is the output
//!   of round `i`, and row `rounds` is `E(x)`.
//! - `constant` is a fixed column holding round constant `c_i` at row `i`.
//! - The round gate is enabled on rows `0 .. rounds - 1` and relates
//!   `state(i + 1)` to the round function of `state(i)` and `c_i`.
//! - The statement gate is enabled on row `rounds` and relates the final
//!   state, `preimage` and `hash`.
//! - `preimage` is copy-constrained to the row-0 state.
//! - `hash` is constrained to the instance column at row 0.
//!
//! The sizing helper and the tests assume one instance column that holds the
//! public hash `h` in row 0. Keep that convention, or update
//! [`INSTANCE_COLUMNS_FOR_SIZING`] and the tests with the layout.
//!
//! # Sizing
//!
//! Halo2 needs a domain `2^k` before any key can be generated. [`params_k`]
//! synthesises the circuit with [`MockProver`] and returns the smallest `k` that
//! the synthesis fits. The adapter builds the IPA parameters from that `k`, so
//! the parameters cannot drift from the layout.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use mimc::{MimcParams, Statement};

/// Instance columns that [`params_k`] assumes.
///
/// The statement has one public value, so one instance column is the natural
/// layout and the tests use it too. A layout with more instance columns must
/// update this constant.
pub const INSTANCE_COLUMNS_FOR_SIZING: usize = 1;

/// Largest domain exponent that [`params_k`] tries.
///
/// [`halo2_proofs::poly::commitment::Params::new`] asserts `k < 32`.
pub const MAX_K: u32 = 31;

/// Halo2 configuration for the MiMC circuit.
///
/// `Circuit::Config` requires `Clone`, so the configuration derives it.
#[derive(Clone, Debug)]
pub struct Config {
    pub state: Column<Advice>,
    pub constant: Column<Fixed>,
    pub round: Selector,
    pub instance: Column<Instance>,
    pub preimage: Column<Advice>,
    pub hash: Column<Advice>,
    pub finish: Selector,
}
/// Halo2 circuit for the MiMC preimage statement.
///
/// The shared circuit type is aliased with the Pasta field.
pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<Fp>;

/// Expected number of domain rows for `rounds` MiMC rounds.
///
/// This is the test oracle for the layout, in the same way that
/// [`crate::plonk::gate_count`] is the oracle for the PLONK layout. The value
/// includes the blinding rows that key generation reserves after the circuit
/// rows, so `domain_rows(rounds).next_power_of_two()` is the smallest domain
/// that holds the circuit.
///
/// The layout uses `rounds + 1` rows: one per round plus the final state. The
/// gates query `state` at `cur` and `next`, and `preimage` and `hash` at `cur`,
/// so the blinding factor is `max(3, 2) + 2 = 5`. Key generation needs
/// `2^k >= rows + blinding + 1`, and the minimum is `blinding + 3 = 8`.
pub fn domain_rows(rounds: usize) -> usize {
    (rounds + 7).max(8)
}

/// Smallest `k` such that `2^k >= rows`.
pub fn k_for_rows(rows: usize) -> u32 {
    let mut k = 0u32;
    while (1usize << k) < rows {
        k += 1;
    }
    k
}

/// Smallest domain exponent that holds the circuit for `params`.
///
/// The circuit is synthesised with [`MockProver`], which places every cell and
/// copy through the circuit's floor planner and rejects a row outside the usable
/// domain. That makes the result a measured size, not a hand-computed formula.
///
/// The witness values are placeholders. Synthesis and row placement do not
/// depend on them, so any preimage works. Both the hash and the instance value
/// are zero, so the pass does not need the real statement.
///
/// [`MockProver::run`] requires a value for every instance column, so the pass
/// uses [`INSTANCE_COLUMNS_FOR_SIZING`] dummy columns.
pub fn params_k(params: &MimcParams<Fp>) -> Result<u32, Error> {
    let circuit = MimcPreimageCircuit {
        statement: Statement {
            params: params.clone(),
            hash: Fp::from(0u64),
            preimage: Some(Fp::from(0u64)),
        },
    };
    let instance = vec![vec![Fp::from(0u64)]; INSTANCE_COLUMNS_FOR_SIZING];

    let fits = |k: u32| -> Result<bool, Error> {
        match MockProver::run(k, &circuit, instance.clone()) {
            Ok(_) => Ok(true),
            Err(Error::NotEnoughRowsAvailable { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    };

    // A larger domain always holds the same circuit, so the predicate is
    // monotone. The scan is linear in `k` and only runs in the untimed
    // universal preparation; probes below `k = 3` do no synthesis because
    // `MockProver` rejects them on `minimum_rows` first.
    for k in 1..=MAX_K {
        if fits(k)? {
            return Ok(k);
        }
    }

    Err(Error::NotEnoughRowsAvailable { current_k: MAX_K })
}

impl Circuit<Fp> for MimcPreimageCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            statement: Statement {
                params: self.statement.params.clone(),
                hash: self.statement.hash,
                preimage: None,
            },
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = meta.advice_column();
        let constant = meta.fixed_column();
        let round = meta.selector();
        let instance = meta.instance_column();
        let preimage = meta.advice_column();
        let hash = meta.advice_column();
        let finish = meta.selector();

        meta.enable_equality(state);
        meta.enable_equality(instance);
        meta.enable_equality(preimage);
        meta.enable_equality(hash);

        meta.create_gate("mimc round", |meta| {
            let enabled = meta.query_selector(round);
            let s = meta.query_advice(state, Rotation::cur());
            let c = meta.query_fixed(constant);
            let next = meta.query_advice(state, Rotation::next());

            let t1 = s + c;
            let t2 = t1.clone().square();
            let t4 = t2.square();
            let t5 = t4 * t1;

            vec![enabled * (t5 - next)]
        });

        meta.create_gate("mimc statement", |meta| {
            let fin_enabled = meta.query_selector(finish);
            let s = meta.query_advice(state, Rotation::cur());
            let x = meta.query_advice(preimage, Rotation::cur());
            let h = meta.query_advice(hash, Rotation::cur());

            vec![fin_enabled * ((s + x) - h)]
        });

        Config {
            state,
            constant,
            round,
            instance,
            preimage,
            hash,
            finish,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let params = &self.statement.params;
        let rounds = params.rounds;

        // The witness is known while proving and unknown while generating keys.
        let x = match self.statement.preimage {
            Some(x) => Value::known(x),
            None => Value::unknown(),
        };
        let hash = Value::known(self.statement.hash);

        let hash_cell = layouter.assign_region(
            || "mimc",
            |mut region| {
                // Rows 0 ..= rounds hold the chain: row 0 is the preimage and
                // row i + 1 is the output of round i.
                let mut state = x;
                let first_state = region.assign_advice(|| "state", config.state, 0, || state)?;

                for (row, constant) in params.round_constants.iter().enumerate() {
                    region.assign_fixed(
                        || "constant",
                        config.constant,
                        row,
                        || Value::known(*constant),
                    )?;
                    config.round.enable(&mut region, row)?;

                    let next = region.assign_advice(
                        || "state",
                        config.state,
                        row + 1,
                        || {
                            // TODO: the round value for row `row + 1`, computed from
                            // `state` and `*constant` in `Value<Fp>` arithmetic.
                            // This closure runs once, in the assignment pass, so the
                            // chain is not recomputed by the shape pass.
                            let t1 = state + Value::known(*constant);
                            let t2 = t1 * t1;
                            let t4 = t2 * t2;
                            t4 * t1
                        },
                    )?;
                    state = next.value().copied();
                }

                // The finish gate reads the final state at `cur`, so it is
                // enabled on the row after the last round, where that state is
                // E(x).
                let finish_row = rounds;
                let preimage_cell =
                    region.assign_advice(|| "preimage", config.preimage, finish_row, || x)?;
                let hash_cell =
                    region.assign_advice(|| "hash", config.hash, finish_row, || hash)?;
                config.finish.enable(&mut region, finish_row)?;

                // The preimage under the hash must be the chain input.
                region.constrain_equal(first_state.cell(), preimage_cell.cell())?;

                Ok(hash_cell)
            },
        )?;

        layouter.constrain_instance(hash_cell.cell(), config.instance, 0)?;
        Ok(())
    }
}
