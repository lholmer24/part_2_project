//! Field adapters for the MiMC core.

use core::fmt::Write as _;

/// Canonical names: the round-constant file stems and the CSV field column.
pub mod names {
    pub const BLS12_381_FR: &str = "bls12_381_fr";
    pub const RISTRETTO255_SCALAR: &str = "ristretto255_scalar";
    pub const PASTA_FP: &str = "pasta_fp";
    pub const WINTERFELL_F128: &str = "winterfell_f128";
}

pub trait MimcField: Copy + Clone + core::fmt::Debug + Eq {
    const NAME: &'static str;

    fn zero() -> Self;

    fn one() -> Self;

    fn from_u64(value: u64) -> Self;

    fn add(self, rhs: Self) -> Self;

    fn mul(self, rhs: Self) -> Self;

    fn to_hex(self) -> String;

    /// Parse one 32-byte block. Returns `None` when the integer is at least the
    /// modulus, which makes rejection sampling exactly uniform.
    fn from_uniform_bytes(bytes: &[u8; 32]) -> Option<Self>;

    /// Accumulate digits with field operations, so constants may exceed 64 bits.
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

/// Expand with Blake3-XOF and reject blocks at or above the modulus, so the
/// result is exactly uniform over the field.
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

// dusk-plonk uses its own BLS12-381 scalar type. Same modulus and canonical
// little-endian encoding as `ark_bls12_381::Fr`, so both share one constant
// file and one field name.
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
