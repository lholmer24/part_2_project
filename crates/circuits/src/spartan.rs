//! The MiMC preimage statement as a Spartan R1CS.
//!
//! Spartan 0.9 takes the three sparse R1CS matrices as `(row, column, value)`
//! triples. The value is a canonical little-endian Ristretto255 scalar encoded
//! as 32 bytes. The Spartan field type is not public, so this module uses the
//! shared [`curve25519_dalek_v4::scalar::Scalar`] adapter and converts each
//! coefficient with [`scalar_bytes`].
//!
//! # Constraint layout
//!
//! One MiMC round is `s -> (s + c)^5` with exponent 5. The addition chain
//! `2, 4, 5` costs three multiplication constraints:
//!
//! ```text
//! A_1 * B_1 = C_1    (s + c) * (s + c) = t2
//! A_2 * B_2 = C_2    t2 * t2           = t4
//! A_3 * B_3 = C_3    t4 * (s + c)      = s'
//! ```
//!
//! The final equality binds the public hash:
//!
//! ```text
//! A_4 * B_4 = C_4    (s_r + x) * 1 = h
//! ```
//!
//! Each round contributes three constraints and three witness variables. The
//! final equality contributes one more constraint and one public input.
//!
//! # Column layout
//!
//! [`Instance::new`] takes the witness columns first, then one constant-one
//! column, then the public-input columns. In witness order, column 0 holds the
//! preimage `x`. Each round then appends `t2`, `t4` and its output `s'`. The
//! constant column follows the last witness column, and the public hash follows
//! the constant.
//!
//! The witness order is the preimage `x`, then `t2`, `t4` and `s'` for each
//! round in order. The helpers [`constant_column`] and [`input_column`] give
//! the constant and input columns.
//!
//! # Generator sizing
//!
//! [`spartan_lib::SNARKGens::new`] pads `num_vars` but not `num_cons`. It
//! calls `num_cons.log_2()` in `R1CSCommitmentGens`, while [`Instance::new`]
//! pads `num_cons` to a power of two. Callers must therefore pass
//! [`R1CSShape::padded_num_cons`], not [`R1CSShape::num_cons`], to
//! `SNARKGens::new`.
//!
//! The builder records its own sizes in [`R1CSShape`]. Do not size anything
//! from a hand-written count; expected counts belong in the tests.

use curve25519_dalek_v4::scalar::Scalar;
use mimc::{MimcParams, Statement};
use spartan_lib::{InputsAssignment, Instance, VarsAssignment};

/// Spartan R1CS circuit for the MiMC preimage statement.
///
/// The shared circuit type is aliased with the Spartan field.
pub type MimcPreimageCircuit = crate::MimcPreimageCircuit<Scalar>;

/// One coefficient in one of the three R1CS matrices.
///
/// `row` and `column` index the matrix. `value` is the canonical
/// little-endian encoding of the coefficient.
pub type MatrixEntry = (usize, usize, [u8; 32]);

/// The three sparse R1CS matrices for one MiMC statement.
///
/// `num_cons`, `num_vars` and `num_inputs` are the unpadded sizes. Spartan
/// pads them inside [`Instance::new`].
pub struct R1CSShape {
    /// Number of constraints before padding.
    pub num_cons: usize,
    /// Number of witness variables before padding.
    pub num_vars: usize,
    /// Number of public inputs.
    pub num_inputs: usize,
    /// Matrix `A`.
    pub a: Vec<MatrixEntry>,
    /// Matrix `B`.
    pub b: Vec<MatrixEntry>,
    /// Matrix `C`.
    pub c: Vec<MatrixEntry>,
}

impl R1CSShape {
    /// Number of constraints after Spartan's power-of-two padding.
    ///
    /// `Instance::new` keeps at least two constraints. `SNARKGens::new` does
    /// not pad `num_cons`, so this value must be passed to it.
    pub fn padded_num_cons(&self) -> usize {
        self.num_cons.next_power_of_two().max(2)
    }

    /// Largest number of non-zero entries in any of the three matrices.
    ///
    /// This is the `num_nz_entries` argument of `SNARKGens::new`.
    pub fn max_nonzeros(&self) -> usize {
        self.a.len().max(self.b.len()).max(self.c.len())
    }

    /// Build the Spartan instance from the three matrices.
    ///
    /// `Instance::new` pads `num_cons` and `num_vars` itself, so the shape's
    /// unpadded sizes are passed through.
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

/// Witness and public-input assignments for one MiMC statement.
pub struct Assignments {
    /// Assignment of the witness variables.
    pub vars: VarsAssignment,
    /// Assignment of the public inputs.
    pub inputs: InputsAssignment,
}

/// R1CS instance and assignments for one MiMC statement.
pub struct MimcInstance {
    /// Sparse R1CS instance.
    pub instance: Instance,
    /// Witness assignment.
    pub vars: VarsAssignment,
    /// Public input assignment.
    pub inputs: InputsAssignment,
}

/// Errors from the Spartan R1CS builder.
#[derive(Debug)]
pub enum Error {
    /// The R1CS instance or an assignment could not be built.
    ///
    /// Spartan does not export its error type, so this variant carries no
    /// detail.
    R1CS,
    /// The statement has no private preimage.
    MissingWitness,
    /// The round function only supports exponent 5.
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

/// Canonical little-endian bytes of one coefficient.
pub fn scalar_bytes(value: Scalar) -> [u8; 32] {
    value.to_bytes()
}

/// Column of the constant one.
pub fn constant_column(num_vars: usize) -> usize {
    num_vars
}

/// Column of public input `input`.
pub fn input_column(num_vars: usize, input: usize) -> usize {
    num_vars + 1 + input
}

/// Build the three sparse R1CS matrices for one MiMC statement.
///
/// The matrices depend on the round count and the round constants, not on the
/// preimage or the public hash.
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

/// Build the witness and public-input assignments for one MiMC statement.
///
/// The witness order must match the columns used by [`build_shape`].
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

/// Build the public-input assignment for one public hash.
///
/// The verifier needs no witness.
pub fn build_inputs(hash: Scalar) -> Result<InputsAssignment, Error> {
    InputsAssignment::new(&[scalar_bytes(hash)]).map_err(|_| Error::R1CS)
}

/// Build the R1CS instance and assignments for one MiMC statement.
///
/// This combines [`build_shape`] and [`build_assignments`]. It is used by the
/// acceptance tests. The adapter builds the shape in setup and the
/// assignments in prove, to keep the timing boundaries separate.
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
