//! Shared MiMC support for every proof system.
//!
//! Skeleton only. The reference hash, field adapters, round-constant loader and
//! cross-language test vectors are part of the MiMC work package.

/// MiMC parameters for one field and one round count.
#[derive(Clone, Debug)]
pub struct MimcParams<F> {
    /// Number of rounds, r.
    pub rounds: usize,
    /// Round-function exponent, e, with gcd(e, q - 1) = 1.
    pub exponent: u64,
    /// Encryption key, k.
    pub key: F,
    /// Round constants c_0, ..., c_{r-1}.
    pub round_constants: Vec<F>,
}
