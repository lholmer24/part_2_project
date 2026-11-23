# Parameters

MiMC uses the native scalar field of each system. The statement is knowledge of
`x` such that `E(x) + x = h`.

| System | Crate | Field | `gcd(e, q-1)` | `e` | Round counts | Security parameters | Estimated security |
|:---|:---|:---|:---:|:---:|:---|:---|:---|
| Groth16 | `ark-groth16` 0.6.0 | BLS12-381 `Fr` | 1 | 5 | `2^k`, `k=0..15` | 255-bit pairing | ~128-bit classical |
| PLONK | `dusk-plonk` 0.24.0 | BLS12-381 `Fr` | 1 | 5 | `2^k`, `k=0..15` | 255-bit pairing + KZG | ~128-bit classical |
| Bulletproofs | `bulletproofs` git `464acb7` | Ristretto255 scalar | 1 | 5 | `2^k`, `k=0..15` | 253-bit group | ~126-bit classical |
| STARK | `winterfell` 0.13.1 | winterfell `f128` | 1 | 5 | `2^k`, `k=0..15` | 42 queries, blowup 8<br>grinding 0, no extension<br>Blake3-256 | 125-bit conjectured |
| Halo2 | `halo2_proofs` 0.4.1 | Pasta `Fp` | 1 | 5 | `2^k`, `k=0..15` | 255-bit group + IPA | ~128-bit classical |
| Spartan | `spartan` 0.9.0 | Ristretto255 scalar | 1 | 5 | `2^k`, `k=0..15` | 253-bit group | ~126-bit classical |

`e = 5` is coprime to `q - 1` in every row, so `x -> x^5` is a permutation.

The STARK grinding factor is 0. Winterfell computes the conjectured security
as `min(min(field_bits, log2(blowup) * queries + grinding) - 1, 128)`, so with
42 queries and blowup 8 the query term alone gives 125 bits. Grinding 16
reaches the 127-bit ceiling of the 128-bit `f128` modulus, so any factor of 2
or more adds no estimated security. The factor also adds a nonce search to
every proof, which widens the prove-time spread. To reach 127 bits without
grinding, raise the query count to 43.

The Halo2 domain exponent `k` is not fixed here: `circuits::halo2::params_k`
measures it per configuration from the chosen gate layout, and one IPA `Params`
is cached for each measured `k`.

The round function is `F_i(x) = (x + c_i)^5`, `E(x) = (F_{r-1} o ... o F_0)(x)`,
and the public hash is `E(x) + x`.
