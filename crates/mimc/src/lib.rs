//! Shared MiMC support for every proof system.

pub mod field;
pub mod statement;

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

pub use field::{names as field_names, uniform_from_seed, MimcField};
pub use statement::Statement;

/// Number of committed constants per field.
pub const MAX_ROUNDS: usize = 1 << 15;

#[derive(Clone, Debug)]
pub struct MimcParams<F> {
    pub rounds: usize,
    pub exponent: u64,
    /// Shared so cloning the parameters copies one pointer.
    pub round_constants: Arc<[F]>,
}

impl<F: MimcField> MimcParams<F> {
    pub fn new(rounds: usize, exponent: u64, round_constants: Vec<F>) -> Result<Self, LoadError> {
        if !(1..=MAX_ROUNDS).contains(&rounds) {
            return Err(LoadError::BadRounds(rounds));
        }
        if round_constants.len() != rounds {
            return Err(LoadError::CountMismatch {
                rounds,
                constants: round_constants.len(),
            });
        }
        Ok(Self {
            rounds,
            exponent,
            round_constants: round_constants.into(),
        })
    }

    pub fn load(rounds: usize, exponent: u64) -> Result<Self, LoadError> {
        Self::new(rounds, exponent, load_round_constants(rounds)?)
    }
}

#[derive(Debug)]
pub enum LoadError {
    BadRounds(usize),
    Io(std::io::Error),
    Parse { line: usize, text: String },
    NotEnough { wanted: usize, found: usize },
    CountMismatch { rounds: usize, constants: usize },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRounds(rounds) => {
                write!(f, "round count must be in 1..={MAX_ROUNDS}, got {rounds}")
            }
            Self::Io(error) => write!(f, "cannot read round constants: {error}"),
            Self::Parse { line, text } => {
                write!(f, "line {line} is not a field element: {text:?}")
            }
            Self::NotEnough { wanted, found } => {
                write!(f, "expected {wanted} constants, found {found}")
            }
            Self::CountMismatch { rounds, constants } => {
                write!(
                    f,
                    "round count {rounds} does not match {constants} constants"
                )
            }
        }
    }
}

impl Error for LoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

pub fn load_round_constants<F: MimcField>(rounds: usize) -> Result<Vec<F>, LoadError> {
    if !(1..=MAX_ROUNDS).contains(&rounds) {
        return Err(LoadError::BadRounds(rounds));
    }

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../params/round_constants")
        .join(format!("{}.txt", F::NAME));
    let text = fs::read_to_string(&path).map_err(LoadError::Io)?;

    let mut constants = Vec::with_capacity(rounds);
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value = F::from_decimal(line).ok_or_else(|| LoadError::Parse {
            line: index + 1,
            text: line.to_string(),
        })?;
        constants.push(value);
        if constants.len() == rounds {
            break;
        }
    }

    if constants.len() != rounds {
        return Err(LoadError::NotEnough {
            wanted: rounds,
            found: constants.len(),
        });
    }
    Ok(constants)
}

pub fn round_function<F: MimcField>(state: F, constant: F, exponent: u64) -> F {
    state.add(constant).pow_u64(exponent)
}

/// Public hash `E(x) + x`.
pub fn hash<F: MimcField>(params: &MimcParams<F>, x: F) -> F {
    debug_assert_eq!(
        params.rounds,
        params.round_constants.len(),
        "round count must match the number of round constants"
    );

    let mut state = x;
    for index in 0..params.rounds {
        let constant: F = params.round_constants[index];
        state = round_function(state, constant, params.exponent);
    }
    state.add(x)
}
