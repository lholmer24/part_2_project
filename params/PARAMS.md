# Parameters

MiMC uses the native scalar field of each system. The statement is knowledge of
`x` such that `E(x) + x = h`.

| System | Crate | Field | `gcd(e, q-1)` | `e` | Round counts | Security parameters | Estimated security |
|:---|:---|:---|:---:|:---:|:---|:---|:---|
| Groth16 | `ark-groth16` 0.6.0 | BLS12-381 `Fr` | 1 | 5 | `2^k`, `k=0..15` | 255-bit pairing | ~128-bit classical |
| PLONK | `dusk-plonk` 0.24.0 | BLS12-381 `Fr` | 1 | 5 | `2^k`, `k=0..15` | 255-bit pairing + KZG | ~128-bit classical |
| Bulletproofs | `bulletproofs` git `464acb7` | Ristretto255 scalar | 1 | 5 | `2^k`, `k=0..15` | 253-bit group | ~126-bit classical |
| STARK | `winterfell` 0.13.1 | winterfell `f128` | 1 | 5 | `2^k`, `k=0..15` | 42 queries, blowup 8<br>grinding 16, no extension<br>Blake3-256 | 127-bit conjectured |
| Halo2 | `halo2_proofs` 0.4.1 | Pasta `Fp` | 1 | 5 | `2^k`, `k=0..15` | 255-bit group + IPA | ~128-bit classical |
| Spartan | `spartan` 0.9.0 | Ristretto255 scalar | 1 | 5 | `2^k`, `k=0..15` | 253-bit group | ~126-bit classical |

`e = 5` is coprime to `q - 1` in every row, so `x -> x^5` is a permutation.

The round function is `F_i(x) = (x + c_i)^5`, `E(x) = (F_{r-1} o ... o F_0)(x)`,
and the public hash is `E(x) + x`.
