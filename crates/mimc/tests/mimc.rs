//! MiMC reference tests.
//!
//! The hash tests run by default. The full round-count sweep and the
//! Rust/Python agreement check need `--features extended-tests`.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use mimc::{hash, load_round_constants, MimcField, MimcParams, MAX_ROUNDS};

/// One SplitMix64 step, used to make the agreement inputs reproducible.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

macro_rules! field_tests {
    ($module:ident, $field:ty) => {
        mod $module {
            use super::*;

            type F = $field;

            #[test]
            fn loads_common_round_counts() {
                for rounds in [1usize, 2, 8, 1024] {
                    let constants = load_round_constants::<F>(rounds).expect("load constants");
                    assert_eq!(constants.len(), rounds);
                }
            }

            #[test]
            #[cfg_attr(
                not(feature = "extended-tests"),
                ignore = "extended: run with --features extended-tests"
            )]
            fn loads_every_round_count() {
                for k in 0..=15 {
                    let rounds = 1usize << k;
                    let constants = load_round_constants::<F>(rounds).expect("load constants");
                    assert_eq!(constants.len(), rounds);
                }
            }

            #[test]
            fn rejects_bad_round_counts() {
                assert!(load_round_constants::<F>(0).is_err());
                assert!(load_round_constants::<F>(MAX_ROUNDS + 1).is_err());
            }

            #[test]
            fn loads_matching_params() {
                let params = MimcParams::<F>::load(8, 5).expect("load params");
                assert_eq!(params.rounds, 8);
                assert_eq!(params.exponent, 5);
                assert_eq!(params.round_constants.len(), 8);
            }

            #[test]
            fn parses_decimal() {
                assert_eq!(F::from_decimal("0"), Some(F::zero()));
                assert_eq!(F::from_decimal("10"), Some(F::from_u64(10)));
                assert_eq!(F::from_decimal("-1"), None);
                assert_eq!(F::from_decimal("1x"), None);
            }

            #[test]
            fn formats_hex() {
                assert_eq!(F::from_u64(0).to_hex(), "0");
                assert_eq!(F::from_u64(255).to_hex(), "ff");
            }

            #[test]
            fn hash_is_deterministic() {
                let params = MimcParams::<F>::load(8, 5).expect("load params");
                let x = F::from_u64(12345);
                assert_eq!(hash(&params, x), hash(&params, x));
            }

            #[test]
            fn hash_depends_on_input() {
                let params = MimcParams::<F>::load(8, 5).expect("load params");
                assert_ne!(hash(&params, F::zero()), hash(&params, F::one()));
            }
        }
    };
}

field_tests!(bls12_381, ark_bls12_381::Fr);
field_tests!(ristretto_v3, curve25519_dalek_v3::scalar::Scalar);
field_tests!(ristretto_v4, curve25519_dalek_v4::scalar::Scalar);
field_tests!(pasta, pasta_curves::Fp);
field_tests!(winterfell, winter_math::fields::f128::BaseElement);

macro_rules! push_vectors {
    ($request:ident, $inputs:ident, $field:ty) => {{
        for k in 0..=15 {
            let rounds = 1usize << k;
            let params = MimcParams::<$field>::load(rounds, 5).expect("load params");
            for &x in &$inputs {
                let value = hash(&params, <$field>::from_u64(x));
                writeln!(
                    $request,
                    "{} {} {} {}",
                    <$field as MimcField>::NAME,
                    rounds,
                    x,
                    value.to_hex()
                )
                .expect("format one vector");
            }
        }
    }};
}

#[test]
#[cfg_attr(
    not(feature = "extended-tests"),
    ignore = "extended: run with --features extended-tests"
)]
fn rust_and_python_agree() {
    let mut state = 0x5EED_1234_5678_9ABC_u64;
    let inputs: Vec<u64> = (0..100).map(|_| splitmix64(&mut state)).collect();

    let mut request = String::new();
    push_vectors!(request, inputs, ark_bls12_381::Fr);
    push_vectors!(request, inputs, curve25519_dalek_v3::scalar::Scalar);
    push_vectors!(request, inputs, curve25519_dalek_v4::scalar::Scalar);
    push_vectors!(request, inputs, pasta_curves::Fp);
    push_vectors!(request, inputs, winter_math::fields::f128::BaseElement);

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../python/tests/check_vectors.py");
    let venv = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../python/.venv/bin/python");
    let program = if venv.exists() {
        venv.into_os_string()
    } else {
        "python3".into()
    };

    let mut child = Command::new(program)
        .arg(script)
        .stdin(Stdio::piped())
        .spawn()
        .expect("start the Python checker");
    {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin
            .write_all(request.as_bytes())
            .expect("write the vectors to the checker");
    }
    let status = child.wait().expect("wait for the Python checker");
    assert!(status.success(), "the Python checker rejected the vectors");
}
