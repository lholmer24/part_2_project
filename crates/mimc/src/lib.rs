//! Shared MiMC support for every proof system.
//!
//! The hash is `E(x) + x` over `r` rounds, in the native scalar field of each
//! proof system. Round constants come from `params/round_constants/`.

pub mod field;

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

pub use field::{names as field_names, MimcField};

/// The committed constant files hold 2^15 entries per field.
pub const MAX_ROUNDS: usize = 1 << 15;

/// MiMC parameters for one field and one round count.
#[derive(Clone, Debug)]
pub struct MimcParams<F> {
    /// Number of rounds, r.
    pub rounds: usize,
    /// Round-function exponent, e, with gcd(e, q - 1) = 1.
    pub exponent: u64,
    /// Round constants c_0, ..., c_{r-1}, shared so cloning is cheap.
    pub round_constants: Arc<[F]>,
}

impl<F: MimcField> MimcParams<F> {
    /// Build parameters from an already loaded constant list.
    ///
    /// Returns [`LoadError::CountMismatch`] when the list length is not
    /// `rounds`, and [`LoadError::BadRounds`] when `rounds` is out of range.
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

    /// Load the constants for round count `rounds` from the shared files.
    pub fn load(rounds: usize, exponent: u64) -> Result<Self, LoadError> {
        Self::new(rounds, exponent, load_round_constants(rounds)?)
    }
}

/// Error from loading the shared round constants.
#[derive(Debug)]
pub enum LoadError {
    /// The requested round count is outside `1..=MAX_ROUNDS`.
    BadRounds(usize),
    /// The constant file could not be read.
    Io(std::io::Error),
    /// A line is not a decimal field element.
    Parse {
        /// One-based line number in the constant file.
        line: usize,
        /// The offending text.
        text: String,
    },
    /// The file holds fewer constants than requested.
    NotEnough {
        /// Number of constants requested.
        wanted: usize,
        /// Number of constants found.
        found: usize,
    },
    /// The round count and the supplied constant count disagree.
    CountMismatch {
        /// Number of rounds requested.
        rounds: usize,
        /// Number of constants supplied.
        constants: usize,
    },
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

/// Load the first `rounds` constants for field `F`.
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

/// Apply one MiMC round to `state`.
pub fn round_function<F: MimcField>(state: F, constant: F, exponent: u64) -> F {
    state.add(constant).pow_u64(exponent)
}

/// Compute the public hash `E(x) + x` for the given parameters.
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
