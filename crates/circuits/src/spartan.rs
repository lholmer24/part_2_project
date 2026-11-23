//! Spartan MiMC preimage circuit.
//!
//! Spartan takes the three sparse R1CS matrices as `(row, column, value)`
//! triples, with each value a canonical little-endian Ristretto255 scalar. One
//! round `s -> (s + c)^5` uses the 2-4-5 chain:
//!
//! ```text
//! (s + c) * (s + c) = t2
//! t2 * t2           = t4
//! t4 * (s + c)      = s'
//! ```
//!
//! and the finish constraint is `(s_r + x) * 1 = h`. Each round contributes
//! three constraints and three witness variables; the finish adds one
//! constraint and one public input.
//!
//! Witness columns are `x`, then `t2, t4, s'` per round, followed by a
//! constant-one column and the public input.
//!
//! `SNARKGens::new` pads `num_vars` but not `num_cons`: it calls
//! `num_cons.log_2()`, while `Instance::new` pads `num_cons` to a power of two.
//! Callers must pass [`R1CSShape::padded_num_cons`].

use curve25519_dalek_v4::scalar::Scalar;
use mimc::{MimcParams, Statement};
use spartan_lib::{InputsAssignment, Instance, VarsAssignment};

pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<Scalar>;

pub type MatrixEntry = (usize, usize, [u8; 32]);

pub struct R1CSShape {
    pub num_cons: usize,
    pub num_vars: usize,
    pub num_inputs: usize,
    pub a: Vec<MatrixEntry>,
    pub b: Vec<MatrixEntry>,
    pub c: Vec<MatrixEntry>,
}

impl R1CSShape {
    pub fn padded_num_cons(&self) -> usize {
        self.num_cons.next_power_of_two().max(2)
    }

    pub fn max_nonzeros(&self) -> usize {
        self.a.len().max(self.b.len()).max(self.c.len())
    }

    pub fn instance(&self) -> Result<Instance, Error> {
        Instance::new(
            self.num_cons,
            self.num_vars,
            self.num_inputs,
            &self.a,
            &self.b,
            &self.c,
        )
        .map_err(|_| Error::R1CS)
    }
}

pub struct Assignments {
    pub vars: VarsAssignment,
    pub inputs: InputsAssignment,
}

pub struct MimcInstance {
    pub instance: Instance,
    pub vars: VarsAssignment,
    pub inputs: InputsAssignment,
}

#[derive(Debug)]
pub enum Error {
    /// Spartan does not export its error type, so this carries no detail.
    R1CS,
    MissingWitness,
    UnsupportedExponent(u64),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::R1CS => f.write_str("Spartan R1CS construction failed"),
            Self::MissingWitness => f.write_str("the MiMC statement has no preimage"),
            Self::UnsupportedExponent(exponent) => {
                write!(f, "Spartan MiMC only supports exponent 5, got {exponent}")
            }
        }
    }
}

impl std::error::Error for Error {}

pub fn scalar_bytes(value: Scalar) -> [u8; 32] {
    value.to_bytes()
}

pub fn constant_column(num_vars: usize) -> usize {
    num_vars
}

pub fn input_column(num_vars: usize, input: usize) -> usize {
    num_vars + 1 + input
}

/// The matrices depend on the round count and constants, not on the statement.
pub fn build_shape(params: &MimcParams<Scalar>) -> Result<R1CSShape, Error> {
    if params.exponent != 5 {
        return Err(Error::UnsupportedExponent(params.exponent));
    }

    let mut a: Vec<MatrixEntry> = Vec::new();
    let mut b: Vec<MatrixEntry> = Vec::new();
    let mut c: Vec<MatrixEntry> = Vec::new();

    // Constant-column terms are deferred until `num_vars` is known.
    let mut a_constants: Vec<(usize, [u8; 32])> = Vec::new();
    let mut b_constants: Vec<(usize, [u8; 32])> = Vec::new();

    let mut next_row = 0usize;
    let mut next_var = 1usize; // column 0 is the preimage x
    let mut state_var = 0usize;

    let one = scalar_bytes(Scalar::from(1u64));
    for constant in params.round_constants.iter() {
        let c_bytes = scalar_bytes(*constant);

        let t2 = next_var;
        let t4 = next_var + 1;
        let next_state = next_var + 2;
        next_var += 3;

        // (s + c) * (s + c) = t2
        a.push((next_row, state_var, one));
        a_constants.push((next_row, c_bytes));

        b.push((next_row, state_var, one));
        b_constants.push((next_row, c_bytes));

        c.push((next_row, t2, one));
        next_row += 1;

        // t2 * t2 = t4
        a.push((next_row, t2, one));
        b.push((next_row, t2, one));
        c.push((next_row, t4, one));
        next_row += 1;

        // t4 * (s + c) = next_state
        a.push((next_row, t4, one));

        b.push((next_row, state_var, one));
        b_constants.push((next_row, c_bytes));

        c.push((next_row, next_state, one));
        next_row += 1;

        state_var = next_state;
    }

    let num_vars = next_var;
    let input_col = input_column(num_vars, 0);

    // (s + x) * 1 = h
    a.push((next_row, state_var, one));
    a.push((next_row, 0, one));
    b_constants.push((next_row, one));
    c.push((next_row, input_col, one));
    next_row += 1;

    // Place the deferred constant-column terms at `constant_column(num_vars)`.
    let constant_col = constant_column(num_vars);
    for (row, coefficient) in a_constants {
        a.push((row, constant_col, coefficient));
    }
    for (row, coefficient) in b_constants {
        b.push((row, constant_col, coefficient));
    }

    Ok(R1CSShape {
        num_cons: next_row,
        num_vars,
        num_inputs: 1,
        a,
        b,
        c,
    })
}

/// Witness order must match the columns in [`build_shape`].
pub fn build_assignments(
    params: &MimcParams<Scalar>,
    hash: Scalar,
    preimage: Scalar,
) -> Result<Assignments, Error> {
    if params.exponent != 5 {
        return Err(Error::UnsupportedExponent(params.exponent));
    }

    let mut vars = Vec::new();
    vars.push(scalar_bytes(preimage));

    let mut state = preimage;
    for constant in params.round_constants.iter() {
        let sum = state + *constant;
        let t2 = sum * sum;
        let t4 = t2 * t2;
        let next = t4 * sum;
        vars.push(scalar_bytes(t2));
        vars.push(scalar_bytes(t4));
        vars.push(scalar_bytes(next));
        state = next;
    }

    let inputs = vec![scalar_bytes(hash)];

    Ok(Assignments {
        vars: VarsAssignment::new(&vars).map_err(|_| Error::R1CS)?,
        inputs: InputsAssignment::new(&inputs).map_err(|_| Error::R1CS)?,
    })
}

pub fn build_inputs(hash: Scalar) -> Result<InputsAssignment, Error> {
    InputsAssignment::new(&[scalar_bytes(hash)]).map_err(|_| Error::R1CS)
}

/// Convenience wrapper used by the acceptance tests.
pub fn build_instance(circuit: &MimcPreimageCircuit) -> Result<MimcInstance, Error> {
    let Statement {
        params,
        hash,
        preimage,
    } = &circuit.statement;
    let preimage = preimage.ok_or(Error::MissingWitness)?;

    let shape = build_shape(params)?;
    let instance = shape.instance()?;
    let assignments = build_assignments(params, *hash, preimage)?;

    Ok(MimcInstance {
        instance,
        vars: assignments.vars,
        inputs: assignments.inputs,
    })
}
