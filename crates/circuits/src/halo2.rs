//! Halo2 MiMC preimage circuit.
//!
//! Column `state` holds `x, s_1, ..., s_r`, and row `i < r` runs four gates
//! with the `round` selector on the 2-4-5 chain:
//!
//! ```text
//! preimage(row+1) = preimage(row)          (x is carried)
//! square          = (state + c_i)^2
//! fourth          = square^2
//! state(row+1)    = fourth * (state + c_i)
//! ```
//!
//! Row 0 ties `state` to `preimage`, and row `r` checks `state + x = h`
//! against the instance column, so the hash sits at index `rounds` of the
//! instance vector.
//!
//! Both structural choices follow from `halo2_proofs` accounting. A selector
//! adds one degree, and the degree sets the quotient domain and the `h` piece
//! count (`degree - 1`), so the chain is split into degree-2 gates to give 3
//! rather than 6. The permutation argument commits one product polynomial per
//! `max(1, degree - 2)` equality-enabled columns, so degree 3 leaves no room:
//! the circuit enables no equality and carries `x` in an advice column.

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
    pub square: Column<Advice>,
    pub fourth: Column<Advice>,
    /// Carried on every row, so the constant gate replaces a copy constraint.
    pub preimage: Column<Advice>,
    pub constant: Column<Fixed>,
    pub round: Selector,
    pub first: Selector,
    pub finish: Selector,
    pub instance: Column<Instance>,
}

pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<Fp>;

/// The finish gate reads row `rounds`, so the vector is padded to that index.
pub fn instance_values(hash: Fp, rounds: usize) -> Vec<Fp> {
    let mut values = vec![Fp::from(0u64); rounds + 1];
    values[rounds] = hash;
    values
}

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
    let instance = vec![instance_values(Fp::from(0u64), params.rounds)];

    let fits = |k: u32| -> Result<bool, Error> {
        match MockProver::run(k, &circuit, instance.clone()) {
            Ok(_) => Ok(true),
            Err(Error::NotEnoughRowsAvailable { .. }) => Ok(false),
            Err(Error::InstanceTooLarge) => Ok(false),
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
        let square = meta.advice_column();
        let fourth = meta.advice_column();
        let preimage = meta.advice_column();
        let constant = meta.fixed_column();
        let round = meta.selector();
        let first = meta.selector();
        let finish = meta.selector();
        let instance = meta.instance_column();

        meta.create_gate("mimc preimage", |meta| {
            let enabled = meta.query_selector(round);
            let x = meta.query_advice(preimage, Rotation::cur());
            let next = meta.query_advice(preimage, Rotation::next());

            vec![enabled * (next - x)]
        });

        meta.create_gate("mimc square", |meta| {
            let enabled = meta.query_selector(round);
            let s = meta.query_advice(state, Rotation::cur());
            let c = meta.query_fixed(constant);
            let t2 = meta.query_advice(square, Rotation::cur());

            vec![enabled * (t2 - (s + c).square())]
        });

        meta.create_gate("mimc fourth", |meta| {
            let enabled = meta.query_selector(round);
            let t2 = meta.query_advice(square, Rotation::cur());
            let t4 = meta.query_advice(fourth, Rotation::cur());

            vec![enabled * (t4 - t2.square())]
        });

        meta.create_gate("mimc chain", |meta| {
            let enabled = meta.query_selector(round);
            let s = meta.query_advice(state, Rotation::cur());
            let c = meta.query_fixed(constant);
            let t4 = meta.query_advice(fourth, Rotation::cur());
            let next = meta.query_advice(state, Rotation::next());

            vec![enabled * (next - t4 * (s + c))]
        });

        meta.create_gate("mimc start", |meta| {
            let enabled = meta.query_selector(first);
            let s = meta.query_advice(state, Rotation::cur());
            let x = meta.query_advice(preimage, Rotation::cur());

            vec![enabled * (s - x)]
        });

        meta.create_gate("mimc statement", |meta| {
            let enabled = meta.query_selector(finish);
            let s = meta.query_advice(state, Rotation::cur());
            let x = meta.query_advice(preimage, Rotation::cur());
            let h = meta.query_instance(instance, Rotation::cur());

            vec![enabled * ((s + x) - h)]
        });

        Config {
            state,
            square,
            fourth,
            preimage,
            constant,
            round,
            first,
            finish,
            instance,
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

        layouter.assign_region(
            || "mimc",
            |mut region| {
                let mut state = x;

                for row in 0..=rounds {
                    region.assign_advice(|| "preimage", config.preimage, row, || x)?;
                    region.assign_advice(|| "state", config.state, row, || state)?;

                    if row == 0 {
                        config.first.enable(&mut region, row)?;
                    }
                    if row == rounds {
                        config.finish.enable(&mut region, row)?;
                        break;
                    }

                    config.round.enable(&mut region, row)?;
                    region.assign_fixed(
                        || "constant",
                        config.constant,
                        row,
                        || Value::known(params.round_constants[row]),
                    )?;

                    let shifted = state + Value::known(params.round_constants[row]);
                    let squared = shifted * shifted;
                    region.assign_advice(|| "square", config.square, row, || squared)?;
                    region.assign_advice(|| "fourth", config.fourth, row, || squared * squared)?;

                    state = squared * squared * shifted;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}
