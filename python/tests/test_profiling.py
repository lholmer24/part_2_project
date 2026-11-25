from pathlib import Path

from profiling.clean import clean, normalise


def test_normalise_keeps_function_name() -> None:
    assert normalise(" ark_ec::scalar_mul::variable_base::mul ") == (
        "ark_ec::scalar_mul::variable_base::mul"
    )


def test_clean_keeps_demangled_names(tmp_path: Path) -> None:
    source = tmp_path / "folded.raw"
    source.write_text(
        "profile_phase;all;ark_ff::fields::models::fp::Fp<Config, 4>::mul_assign 3\n"
        "profile_phase;all;ark_ff::fields::models::fp::Fp<Config, 4>::mul_assign 2\n"
    )

    total = clean(source, tmp_path / "out")

    assert total == 5
    assert (tmp_path / "out" / "folded.txt").read_text() == (
        "profile_phase;all;ark_ff::fields::models::fp::Fp<Config, 4>::mul_assign 5\n"
    )
    top = (tmp_path / "out" / "top.txt").read_text()
    assert "ark_ff::fields::models::fp::Fp<Config, 4>::mul_assign" in top
