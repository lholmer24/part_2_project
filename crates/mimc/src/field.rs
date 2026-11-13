//! Field adapters for the MiMC core.
//!
//! The proof systems use different scalar-field types. This module gives them
//! one small interface so the MiMC code stays generic.

use core::fmt::Write as _;

/// Canonical field names.
///
/// These are the file stems in `params/round_constants/` and the values written
/// to the CSV `field` column. [`MimcField::NAME`] and the harness adapters both
/// use them, so each name has one definition.
pub mod names {
    /// BLS12-381 scalar field, used by Groth16 and PLONK.
    pub const BLS12_381_FR: &str = "bls12_381_fr";
    /// Ristretto255 scalar field, used by Bulletproofs and Spartan.
    pub const RISTRETTO255_SCALAR: &str = "ristretto255_scalar";
    /// Pasta `Fp`, used by Halo2.
    pub const PASTA_FP: &str = "pasta_fp";
    /// winterfell `f128`, used by STARK.
    pub const WINTERFELL_F128: &str = "winterfell_f128";
}

/// Small interface over a prime field.
///
/// Implementations adapt one concrete field type. The MiMC code only needs
/// addition, multiplication and exponentiation.
pub trait MimcField: Copy + Clone + core::fmt::Debug + Eq {
    /// File stem used in `params/round_constants/<NAME>.txt`.
    const NAME: &'static str;

    /// The additive identity.
    fn zero() -> Self;

    /// The multiplicative identity.
    fn one() -> Self;

    /// Lift a small integer into the field.
    fn from_u64(value: u64) -> Self;

    /// Field addition.
    fn add(self, rhs: Self) -> Self;

    /// Field multiplication.
    fn mul(self, rhs: Self) -> Self;

    /// Canonical hexadecimal representation, without a `0x` prefix.
    fn to_hex(self) -> String;

    /// Parse one 32-byte block as a canonical field element.
    ///
    /// Returns `None` when the block encodes an integer at least the field
    /// modulus. Rejection sampling uses this to produce an exactly uniform
    /// field element from a uniform byte stream.
    fn from_uniform_bytes(bytes: &[u8; 32]) -> Option<Self>;

    /// Parse a decimal integer into the field.
    ///
    /// The default implementation accumulates digits with field operations, so
    /// it handles constants wider than 64 bits.
    fn from_decimal(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let ten = Self::from_u64(10);
        let mut value = Self::zero();
        for byte in text.bytes() {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value.mul(ten).add(Self::from_u64(u64::from(byte - b'0')));
        }
        Some(value)
    }

    /// Exponentiation by a `u64` exponent.
    fn pow_u64(self, mut exponent: u64) -> Self {
        let mut result = Self::one();
        let mut base = self;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exponent >>= 1;
        }
        result
    }
}

/// Sample one field element uniformly from a 32-byte seed.
///
/// The seed is expanded with the Blake3 XOF. Each 32-byte block is interpreted
/// as an unsigned integer and accepted only if it is below the field modulus,
/// so the result is exactly uniform over the field.
pub fn uniform_from_seed<F: MimcField>(seed: &[u8; 32]) -> F {
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut block = [0u8; 32];

    loop {
        reader.fill(&mut block);
        if let Some(value) = F::from_uniform_bytes(&block) {
            return value;
        }
    }
}

/// Format little-endian bytes as a minimal lowercase hex string.
fn hex_from_le_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter().rev() {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    let trimmed = out.trim_start_matches('0');
    if trimmed.is_empty() {
        String::from("0")
    } else {
        trimmed.to_string()
    }
}

impl MimcField for ark_bls12_381::Fr {
    const NAME: &'static str = names::BLS12_381_FR;

    fn zero() -> Self {
        Self::from(0u64)
    }

    fn one() -> Self {
        Self::from(1u64)
    }

    fn from_u64(value: u64) -> Self {
        Self::from(value)
    }

    fn add(self, rhs: Self) -> Self {
        self + rhs
    }

    fn mul(self, rhs: Self) -> Self {
        self * rhs
    }

    fn to_hex(self) -> String {
        use ark_ff::{BigInteger, PrimeField};
        hex_from_le_bytes(&self.into_bigint().to_bytes_le())
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Option<Self> {
        use ark_ff::{BigInteger, PrimeField};
        let candidate = Self::from_le_bytes_mod_order(bytes);
        (candidate.into_bigint().to_bytes_le().as_slice() == bytes.as_slice()).then_some(candidate)
    }
}

// dusk-plonk uses its own BLS12-381 scalar type. It has the same modulus as
// `ark_bls12_381::Fr`, so it shares the same constant file and field name.
// `to_bytes` is canonical little-endian, which matches `hex_from_le_bytes`.
impl MimcField for dusk_bls12_381::BlsScalar {
    const NAME: &'static str = names::BLS12_381_FR;

    fn zero() -> Self {
        Self::zero()
    }

    fn one() -> Self {
        Self::one()
    }

    fn from_u64(value: u64) -> Self {
        Self::from(value)
    }

    fn add(self, rhs: Self) -> Self {
        self + rhs
    }

    fn mul(self, rhs: Self) -> Self {
        self * rhs
    }

    fn to_hex(self) -> String {
        hex_from_le_bytes(&self.to_bytes())
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Option::from(Self::from_bytes(bytes))
    }
}

fn dalek_v3_from_uniform(bytes: &[u8; 32]) -> Option<curve25519_dalek_v3::scalar::Scalar> {
    curve25519_dalek_v3::scalar::Scalar::from_canonical_bytes(*bytes)
}

fn dalek_v4_from_uniform(bytes: &[u8; 32]) -> Option<curve25519_dalek_v4::scalar::Scalar> {
    Option::from(curve25519_dalek_v4::scalar::Scalar::from_canonical_bytes(
        *bytes,
    ))
}

macro_rules! impl_scalar_field {
    ($field:ty, $name:expr, $uniform:path) => {
        impl MimcField for $field {
            const NAME: &'static str = $name;

            fn zero() -> Self {
                Self::from(0u64)
            }

            fn one() -> Self {
                Self::from(1u64)
            }

            fn from_u64(value: u64) -> Self {
                Self::from(value)
            }

            fn add(self, rhs: Self) -> Self {
                self + rhs
            }

            fn mul(self, rhs: Self) -> Self {
                self * rhs
            }

            fn to_hex(self) -> String {
                hex_from_le_bytes(&self.to_bytes())
            }

            fn from_uniform_bytes(bytes: &[u8; 32]) -> Option<Self> {
                $uniform(bytes)
            }
        }
    };
}

impl_scalar_field!(
    curve25519_dalek_v3::scalar::Scalar,
    names::RISTRETTO255_SCALAR,
    dalek_v3_from_uniform
);
impl_scalar_field!(
    curve25519_dalek_v4::scalar::Scalar,
    names::RISTRETTO255_SCALAR,
    dalek_v4_from_uniform
);

impl MimcField for pasta_curves::Fp {
    const NAME: &'static str = names::PASTA_FP;

    fn zero() -> Self {
        Self::from(0u64)
    }

    fn one() -> Self {
        Self::from(1u64)
    }

    fn from_u64(value: u64) -> Self {
        Self::from(value)
    }

    fn add(self, rhs: Self) -> Self {
        self + rhs
    }

    fn mul(self, rhs: Self) -> Self {
        self * rhs
    }

    fn to_hex(self) -> String {
        use ff14::PrimeField;
        hex_from_le_bytes(self.to_repr().as_ref())
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Option<Self> {
        use ff14::PrimeField;
        Option::from(Self::from_repr(*bytes))
    }
}

impl MimcField for winter_math::fields::f128::BaseElement {
    const NAME: &'static str = names::WINTERFELL_F128;

    fn zero() -> Self {
        Self::from(0u64)
    }

    fn one() -> Self {
        Self::from(1u64)
    }

    fn from_u64(value: u64) -> Self {
        Self::from(value)
    }

    fn add(self, rhs: Self) -> Self {
        self + rhs
    }

    fn mul(self, rhs: Self) -> Self {
        self * rhs
    }

    fn to_hex(self) -> String {
        use winter_math::StarkField;
        format!("{:x}", self.as_int())
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Option<Self> {
        use winter_math::StarkField;
        let value = u128::from_le_bytes(
            bytes[..16]
                .try_into()
                .expect("the block always has sixteen bytes"),
        );
        (value < <Self as StarkField>::MODULUS).then(|| Self::new(value))
    }
}
