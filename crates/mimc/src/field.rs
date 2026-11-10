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
}

macro_rules! impl_scalar_field {
    ($field:ty, $name:expr) => {
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
        }
    };
}

impl_scalar_field!(
    curve25519_dalek_v3::scalar::Scalar,
    names::RISTRETTO255_SCALAR
);
impl_scalar_field!(
    curve25519_dalek_v4::scalar::Scalar,
    names::RISTRETTO255_SCALAR
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
}
