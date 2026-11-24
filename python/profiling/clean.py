#!/usr/bin/env python3
"""Clean collapsed stacks for the interactive flame-graph explorer.

Reads folded stacks, maps every frame to a short subsystem label, merges
adjacent duplicates, aggregates equal stacks, and writes:

  folded.txt   the cleaned stacks for inferno-flamegraph
  palette.map  one colour per label, for inferno-flamegraph --cp
  top.txt      inclusive sample counts per label

The label set is deliberately small: raw demangled Rust names are too long to
read at figure size, and generics hide which subsystem owns the time.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

RULES: list[tuple[re.Pattern[str], str, str]] = []


def rule(pattern: str, label: str, category: str) -> None:
    RULES.append((re.compile(pattern), label, category))


# The harness boundary and project code.
rule(r"as harness::System>::(setup|prove|verify)", r"phase \1", "harness")
rule(r"^<?harness::", "harness", "harness")
rule(r"^<?circuits::", "circuit synthesis", "harness")
rule(r"mimc::", "MiMC", "harness")
rule(r"^profile_phase", "driver", "harness")

# Groth16.
rule(r"ark_groth16::r1cs_to_qap", "groth16 QAP", "prover")
rule(r"ark_groth16::prover", "groth16 prover", "prover")
rule(r"ark_groth16::verifier", "groth16 verifier", "prover")
rule(r"ark_groth16::generator", "groth16 keygen", "prover")
rule(r"^<?ark_groth16::", "groth16", "prover")

# dusk-plonk.
rule(r"dusk_plonk::compiler::prover", "dusk prover", "prover")
rule(r"dusk_plonk::compiler::verifier", "dusk verifier", "prover")
rule(r"dusk_plonk::compiler", "dusk compiler", "prover")
rule(r"dusk_plonk::commitment_scheme", "dusk commitment", "poly")
rule(r"dusk_plonk::proof_system::quotient", "dusk quotient", "prover")
rule(r"dusk_plonk::proof_system::permutation", "dusk permutation", "prover")
rule(r"dusk_plonk::proof_system::lookup", "dusk lookup", "prover")
rule(r"dusk_plonk::proof_system::linear", "dusk linearisation", "prover")
rule(r"dusk_plonk::proof_system::widget::logic", "dusk logic gate", "prover")
rule(r"dusk_plonk::proof_system::widget::range", "dusk range gate", "prover")
rule(r"dusk_plonk::proof_system::widget::ecc", "dusk ecc gate", "prover")
rule(r"dusk_plonk::proof_system::widget::permutation", "dusk permutation gate", "prover")
rule(r"dusk_plonk::proof_system::widget", "dusk widgets", "prover")
rule(r"dusk_plonk::proof_system::prover", "dusk prover", "prover")
rule(r"dusk_plonk::proof_system::verifier", "dusk verifier", "prover")
rule(r"dusk_plonk::constraint_system", "dusk constraints", "prover")
rule(r"dusk_plonk.*(fft|polynomial)", "dusk FFT", "poly")
rule(r"^<?dusk_plonk", "dusk-plonk", "prover")
rule(r"dusk_bls12_381.*(multiscalar_mul|msm)", "dusk MSM", "curve")
rule(r"dusk_bls12_381.*(g1|g2)", "dusk curve", "curve")
rule(r"dusk_bls12_381.*(mul|montgomery_reduce|mac)", "dusk field mul", "field")
rule(r"dusk_bls12_381.*(add|sub|subtract_p|sbb|double|neg)", "dusk field add", "field")
rule(r"dusk_bls12_381.*square", "dusk field square", "field")
rule(r"dusk_bls12_381.*(inverse|invert|pow)", "dusk field exponentiation", "field")
rule(r"^<?dusk_bls12_381", "dusk field", "field")

# Halo2. Plonk-specific rules run first because plonk frames mention poly in
# their generic arguments; commitment and MSM frames do not mention plonk.
rule(r"halo2_proofs::plonk::keygen", "halo2 keygen", "prover")
rule(r"halo2_proofs::plonk::prover", "halo2 prover", "prover")
rule(r"halo2_proofs::plonk::verifier", "halo2 verifier", "prover")
rule(r"halo2_proofs::plonk::permutation", "halo2 permutation", "prover")
rule(r"halo2_proofs::plonk::lookup|halo2_proofs::plonk::shuffle", "halo2 lookup", "prover")
rule(r"halo2_proofs::plonk::quotient|halo2_proofs::plonk::vanishing", "halo2 quotient", "prover")
rule(r"halo2_proofs::plonk", "halo2 plonk", "prover")
rule(r"halo2_proofs::poly::commitment::prover::parallel_generator_collapse",
     "halo2 generator collapse", "poly")
rule(r"halo2_proofs::poly::commitment::ipa|halo2_proofs::poly::commitment::msm",
     "halo2 IPA", "curve")
rule(r"halo2_proofs::poly::commitment::kzg", "halo2 KZG", "poly")
rule(r"halo2_proofs::poly::commitment", "halo2 commitment", "poly")
rule(r"halo2_proofs::poly::multiopen", "halo2 multiopen", "poly")
rule(r"halo2_proofs::poly::evaluator", "halo2 poly eval", "poly")
rule(r"halo2_proofs::poly::domain", "halo2 domain", "poly")
rule(r"halo2_proofs::arithmetic::Bucket<", "halo2 bucket add", "curve")
rule(r"halo2_proofs::arithmetic::best_multiexp|halo2_proofs::arithmetic::BoothBuckets",
     "halo2 MSM", "curve")
rule(r"halo2_proofs::arithmetic::fft", "halo2 FFT", "poly")
rule(r"halo2_proofs::arithmetic::parallelize|maybe_rayon", "halo2 parallel", "runtime")
rule(r"halo2_proofs::arithmetic", "halo2 field", "field")
rule(r"halo2_proofs::poly", "halo2 poly", "poly")
rule(r"halo2_proofs::transcript", "halo2 transcript", "hash")
rule(r"^<?halo2_proofs::", "halo2", "prover")
rule(r"pasta_curves::curves", "pasta curve", "curve")
rule(r"pasta_curves::fields.*(mul|montgomery_reduce|mac)|"
     r"pasta_curves::arithmetic::fields.*(mul|montgomery_reduce|mac)", "pasta field mul", "field")
rule(r"pasta_curves::fields.*(add|sub|double)|"
     r"pasta_curves::arithmetic::fields.*(add|sub|double)", "pasta field add", "field")
rule(r"pasta_curves::fields.*square|pasta_curves::arithmetic::fields.*square",
     "pasta field square", "field")
rule(r"pasta_curves::fields|pasta_curves::arithmetic", "pasta field", "field")
rule(r"^<?pasta_curves", "pasta", "curve")

# Bulletproofs.
rule(r"bulletproofs::r1cs::prover", "bulletproofs R1CS prover", "prover")
rule(r"bulletproofs::r1cs::verifier", "bulletproofs R1CS verifier", "prover")
rule(r"bulletproofs::r1cs", "bulletproofs R1CS", "r1cs")
rule(r"bulletproofs::inner_product_proof", "bulletproofs inner product", "prover")
rule(r"bulletproofs::range_proof", "bulletproofs range proof", "prover")
rule(r"bulletproofs::generators", "bulletproofs generators", "curve")
rule(r"bulletproofs::transcript", "bulletproofs transcript", "hash")
rule(r"^<?bulletproofs", "bulletproofs", "prover")

# Spartan.
rule(r"libspartan::SNARK|libspartan::snark", "spartan SNARK", "prover")
rule(r"libspartan::r1csinstance|R1CSEvalProof", "spartan R1CS", "prover")
rule(r"libspartan::product_tree", "spartan product tree", "poly")
rule(r"libspartan::r1csproof", "spartan R1CS proof", "prover")
rule(r"libspartan::sparse_mlpoly", "spartan sparse poly", "poly")
rule(r"libspartan::dense_mlpoly", "spartan dense poly", "poly")
rule(r"libspartan::sumcheck", "spartan sumcheck", "poly")
rule(r"libspartan::commitments|MultiCommitGens|CommitmentGens|Commitments::commit",
     "spartan commitments", "curve")
rule(r"libspartan::group", "spartan MSM", "curve")
rule(r"libspartan::nizk", "spartan NIZK", "prover")
rule(r"libspartan::transcript", "spartan transcript", "hash")
rule(r"libspartan::scalar.*mul", "spartan scalar mul", "field")
rule(r"libspartan::scalar.*(add|sub)", "spartan scalar add", "field")
rule(r"libspartan::scalar", "spartan scalar", "field")
rule(r"^<?libspartan", "spartan", "prover")

# curve25519, shared by Bulletproofs and Spartan.
rule(r"curve25519_dalek::.*(multiscalar_mul|msm)", "curve25519 MSM", "curve")
rule(r"curve25519_dalek::.*(ristretto|edwards|curve_models|window|traits)",
     "curve25519 curve", "curve")
rule(r"curve25519_dalek::.*(field|FieldElement).*(mul|pow2k|square2|square)|"
     r"curve25519_dalek::.*(FieldElement51|FieldElement2625x4)::mul", "curve25519 field mul", "field")
rule(r"curve25519_dalek::.*(field|FieldElement).*(add|sub)", "curve25519 field add", "field")
rule(r"curve25519_dalek::scalar.*mul", "curve25519 field mul", "field")
rule(r"curve25519_dalek::scalar.*(add|sub)", "curve25519 field add", "field")
rule(r"curve25519_dalek::.*(field|FieldElement)|packed_simd|curve25519_dalek::scalar",
     "curve25519 field", "field")
rule(r"^<?curve25519_dalek", "curve25519", "curve")

# Winterfell. The last rule is only for frames that no earlier rule claims.
rule(r"^<?winter_.*(fri|folding|remainder|query|decommit)", "winterfell FRI", "poly")
rule(r"^<?winter_.*(hash|rescue|blake|sha)", "winterfell hash", "hash")
rule(r"winter_math::fft|FftInputs", "winterfell FFT", "poly")
rule(r"^<?winter_.*(fft|ntt)", "winterfell FFT", "poly")
rule(r"^<?winter_prover::matrix.*(evaluate_polys_over|poly)", "winter-prover poly eval", "poly")
rule(r"^<?winter_prover::matrix|^<?winter_prover.*build_segments|Segment<|row_matrix|col_matrix",
     "winter-prover matrix", "prover")
rule(r"^<?winter_prover::trace|^<?winter_prover::domain", "winter-prover trace", "prover")
rule(r"^<?winter_prover::channel|^<?winter_prover::transcript", "winter-prover transcript", "hash")
rule(r"^<?winter_air", "winter-air", "prover")
rule(r"winter_crypto", "winter-crypto", "hash")
rule(r"^<?winter_math::field.*(mul|square|inverse)", "winter-f128 field mul", "field")
rule(r"^<?winter_math::field.*(add|sub)", "winter-f128 field add", "field")
rule(r"^<?winter_math::field|^<?winter_math::fields", "winter-f128 field", "field")
rule(r"^<?winter_math::utils::(serial_)?batch_inversion", "winter-math inversion", "field")
rule(r"^<?winter_math::polynom|^<?winter_math::utils", "winter-math poly", "poly")
rule(r"^<?winter_math", "winter-math", "field")
rule(r"^<?winter_utils", "winter-utils", "runtime")
rule(r"^<?winter_prover", "winter-prover", "prover")
rule(r"^<?winter_verifier|^<?winterfell::verifier|^<?winterfell::verify",
     "winterfell verifier", "prover")
rule(r"winterfell::prover|winterfell::prove", "winterfell prover", "prover")
rule(r"winterfell::proof", "winterfell proof", "prover")
rule(r"^<?winter_|^<?winterfell", "winterfell", "prover")

# Arkworks, narrowed to ark paths so other crates do not fall into these rules.
rule(r"ark_ec.*bucket::Bucket.*(AddAssign|SubAssign|add_assign|sub_assign)",
     "ark-ec bucket add", "curve")
rule(r"ark_ec.*(variable_base|msm|BatchMulPreprocessing|windowed_mul|batch_mul)",
     "ark-ec MSM", "curve")
rule(r"ark_ec.*Projective.*(add_assign|double|AddAssign)", "ark-ec group add", "curve")
rule(r"ark_ec.*(pairing|final_exponentiation|miller_loop|::ell\b)",
     "ark-ec pairing", "curve")
rule(r"ark_ec.*(normalize|batch_convert|into_affine|Affine)", "ark-ec convert", "curve")
rule(r"^<?ark_ec::", "ark-ec", "curve")
rule(r"ark_ff.*sum_of_products|ark_bls12_381::fields.*sum_of_products",
     "ark-ff mont mul", "field")
rule(r"ark_ff.*mul_assign|ark_bls12_381::fields.*mul_assign", "ark-ff mont mul", "field")
rule(r"ark_ff.*square|ark_bls12_381::fields.*square", "ark-ff square", "field")
rule(r"ark_ff.*(add_assign|sub_assign|double_in_place|neg_in_place)|"
     r"ark_bls12_381::fields.*(add_assign|sub_assign|double_in_place|neg_in_place)",
     "ark-ff add", "field")
rule(r"ark_ff.*(cyclotomic|exp_loop|exp_by_x|inverse|invert)|"
     r"ark_bls12_381::fields.*(inverse|invert)", "ark-ff exponentiation", "field")
rule(r"ark_ff::biginteger", "ark-ff bigint mul", "field")
rule(r"^<?ark_ff::|^<?ark_bls12_381::fields", "ark-ff field", "field")
rule(r"ark_poly::domain|ark_poly::fft|Radix2EvaluationDomain", "ark-poly FFT", "poly")
rule(r"ark_poly::(evaluations|polynomial)", "ark-poly poly", "poly")
rule(r"^<?ark_poly::", "ark-poly", "poly")
rule(r"ark_relations|ark_r1cs", "ark-r1cs", "r1cs")
rule(r"ark_serialize", "serialise", "other")

# Hashing, transcripts and randomness.
rule(r"blake3|blake2|sha2|sha3|keccak", "hashing", "hash")
rule(r"merlin|transcript", "transcript", "hash")
rule(r"getrandom|^rand|ark_std::rand|rand_core", "RNG", "other")
rule(r"zeroize", "zeroize", "runtime")

# Generic helpers inherit the enclosing frame.
rule(r"subtle::|core::ops::bit::|SpecArrayEq|as core::cmp::PartialEq>::(eq|ne)|"
     r"as core::ops::index::Index|"
     r"wrapping_mul|wrapping_sub|div_ceil|reverse_bits|copy_from_slice|"
     r"RawVec.*(ptr|non_null|as_ptr)|in_place_collect|write_in_place|"
     r"::swap|TryFrom|MaybeUninit|SliceIndex|Ord>::min|::get\b|"
     r"BTreeMap|btree|drop_glue|drop_in_place|ptr::read|"
     r"PartialOrd|Ordering|>::cmp|::lt\b", "__inherit__", "inherit")
rule(r"^tracing|^<tracing|tracing_core", "__inherit__", "inherit")

# Allocator and runtime noise. Vec and iterator accessors are inlined data
# structure code, so they inherit the enclosing frame rather than the allocator label.
rule(r"^<(alloc::vec::Vec|alloc::vec::into_iter::IntoIter)|"
     r"^alloc::vec::Vec|^alloc::vec::into_iter::IntoIter", "__inherit__", "inherit")
rule(r"RawVec.*(drop|dealloc)|Drop>::drop|dealloc|cfree|__rust_dealloc",
     "allocator free", "allocator")
rule(r"realloc|grow|finish_grow|alloc::alloc|__rust_alloc|posix_memalign|"
     r"malloc|calloc|__rust_no_alloc_shim",
     "allocator alloc", "allocator")
rule(r"^<alloc::|^alloc::|core::alloc|raw_vec|RawVec|btree|BTree",
     "allocator", "allocator")
rule(r"^<?core::|^<?std::", "__inherit__", "inherit")
rule(r"backtrace::|libc\.so|\[libc\.so|"
     r"\[unknown\]|\[kernel", "runtime", "runtime")
rule(r"^(_start|__libc|main$|all$|libc)", "runtime", "runtime")
rule(r"^\(?\[?unknown", "unknown", "other")
rule(r".*", "other", "other")

CATEGORY_COLOURS = {
    "field": (78, 121, 167),
    "curve": (242, 142, 43),
    "poly": (89, 161, 79),
    "hash": (176, 122, 161),
    "r1cs": (156, 117, 95),
    "prover": (225, 87, 89),
    "harness": (118, 183, 178),
    "runtime": (150, 150, 150),
    "allocator": (200, 200, 200),
    "other": (230, 230, 230),
}


def classify(frame: str) -> tuple[str, str]:
    frame = frame.strip().replace("_[i]", "")
    for pattern, label, category in RULES:
        match = pattern.search(frame)
        if match:
            return match.expand(label), category
    return "other", "other"


def clean(source: Path, outdir: Path) -> int:
    outdir.mkdir(parents=True, exist_ok=True)

    stacks: Counter[tuple[str, ...]] = Counter()
    inclusive: Counter[str] = Counter()
    labels: dict[str, str] = {}
    samples = 0

    with source.open() as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            stack, _, count_text = line.rpartition(" ")
            try:
                count = int(count_text)
            except ValueError:
                continue
            frames = []
            for frame in stack.split(";"):
                label, category = classify(frame)
                if category == "inherit":
                    label = frames[-1] if frames else "runtime/alloc"
                else:
                    labels[label] = category
                if frames and frames[-1] == label:
                    continue
                frames.append(label)
            if not frames:
                continue
            stacks[tuple(frames)] += count
            samples += count
            for label in set(frames):
                inclusive[label] += count

    if samples == 0:
        raise ValueError("no samples in folded input")

    with (outdir / "folded.txt").open("w") as handle:
        for frames, count in stacks.most_common():
            handle.write(f"{';'.join(frames)} {count}\n")

    with (outdir / "palette.map").open("w") as handle:
        # inferno draws the synthetic root with the empty-name palette entry.
        handle.write("->rgb(245, 245, 245)\n")
        for label in sorted(labels):
            red, green, blue = CATEGORY_COLOURS[labels[label]]
            handle.write(f"{label}->rgb({red}, {green}, {blue})\n")

    with (outdir / "top.txt").open("w") as handle:
        handle.write(f"total weight: {samples}\n")
        handle.write(f"distinct stacks: {len(stacks)}\n")
        handle.write(f"distinct labels: {len(labels)}\n\n")
        for label, count in inclusive.most_common():
            handle.write(f"{100.0 * count / samples:6.2f}%  {count:7d}  {label}\n")

    return samples

