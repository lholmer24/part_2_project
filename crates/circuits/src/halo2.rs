//! Halo2 MiMC preimage circuit.
//!
//! The `state` column holds `x, s_0, ..., s_r`. A round gate, enabled on rows
//! `0 .. r-1`, enforces
//!
//! ```text
//! state(i + 1) = (state(i) + c_i)^5
//! ```
//!
//! and a finish gate enforces `state(r) + x = h`. `x` is copy-constrained to
//! row 0 and `h` to the instance column.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use mimc::{MimcParams, Statement};

pub const INSTANCE_COLUMNS_FOR_SIZING: usize = 1;

pub const MAX_K: u32 = 31;

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

pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<Fp>;

/// Rows plus five blinding rows. Key generation needs
/// `2^k >= rows + blinding + 1`, with `blinding = max(3, advice queries) + 2`.
pub fn domain_rows(rounds: usize) -> usize {
    (rounds + 7).max(8)
}

pub fn k_for_rows(rows: usize) -> u32 {
    let mut k = 0u32;
    while (1usize << k) < rows {
        k += 1;
    }
    k
}

/// Smallest domain exponent that holds the circuit, measured with
/// `MockProver`. The witness values are placeholders; only the layout matters.
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

    // A larger domain always fits, so the scan is monotone.
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

        let x = match self.statement.preimage {
            Some(x) => Value::known(x),
            None => Value::unknown(),
        };
        let hash = Value::known(self.statement.hash);

        let hash_cell = layouter.assign_region(
            || "mimc",
            |mut region| {
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
                            let t1 = state + Value::known(*constant);
                            let t2 = t1 * t1;
                            let t4 = t2 * t2;
                            t4 * t1
                        },
                    )?;
                    state = next.value().copied();
                }

                // The finish gate reads `cur`, so it sits on the row after the
                // last round, where the state is E(x).
                let finish_row = rounds;
                let preimage_cell =
                    region.assign_advice(|| "preimage", config.preimage, finish_row, || x)?;
                let hash_cell =
                    region.assign_advice(|| "hash", config.hash, finish_row, || hash)?;
                config.finish.enable(&mut region, finish_row)?;

                region.constrain_equal(first_state.cell(), preimage_cell.cell())?;

                Ok(hash_cell)
            },
        )?;

        layouter.constrain_instance(hash_cell.cell(), config.instance, 0)?;
        Ok(())
    }
}
