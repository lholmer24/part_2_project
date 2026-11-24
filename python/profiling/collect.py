"""Collect phase profiles over the round-count sweep and build the explorer.

The default run covers every registered system, every phase it has, and every
power-of-two round count. The benchmark CSV supplies per-configuration medians,
which choose a repetition count that gives roughly `--target-seconds` of
sampled phase per point.
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from . import capture, index

ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = ROOT / "results" / "benchmarks" / "benchmarks.csv"
BINARY = ROOT / "target" / "profiling" / "profile_phase"
ALL_SYSTEMS = ["groth16", "plonk", "bulletproofs", "stark", "halo2", "spartan"]
SETUP_SYSTEMS = {"groth16", "plonk", "halo2", "spartan"}
PHASES = ("setup", "prove", "verify")
MAX_ROUNDS = 1 << 15


def round_counts() -> list[int]:
    return [1 << k for k in range(MAX_ROUNDS.bit_length())]


def read_medians(path: Path) -> dict[tuple[str, str, int], float]:
    if not path.exists():
        print(f"warning: missing {path}; repeating every point once", file=sys.stderr)
        return {}
    samples: dict[tuple[str, str, int], list[int]] = defaultdict(list)
    with path.open() as handle:
        for row in csv.DictReader(handle):
            key = (row["system"], row["phase"], int(row["rounds"]))
            samples[key].append(int(row["time_ns"]))
    return {key: statistics.median(values) for key, values in samples.items()}


def build_profiling_binary() -> None:
    env = os.environ.copy()
    flags = env.get("RUSTFLAGS", "").strip()
    env["RUSTFLAGS"] = f"{flags} -Cforce-frame-pointers=y".strip()
    print("building target/profiling/profile_phase", flush=True)
    subprocess.run(
        ["cargo", "build", "--profile", "profiling", "--bin", "profile_phase"],
        cwd=ROOT,
        env=env,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m profiling",
        description="Collect perf profiles and build results/profiles/index.html.",
    )
    parser.add_argument(
        "--system",
        default="",
        help="comma list; default is every registered system",
    )
    parser.add_argument(
        "--phase", default=",".join(PHASES), help="comma list of setup,prove,verify"
    )
    parser.add_argument("--rounds", default="", help="comma list; default is every power of two")
    parser.add_argument("--target-seconds", type=float, default=0.8)
    parser.add_argument("--max-repeat", type=int, default=5000)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--force", action="store_true", help="recollect existing points")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument(
        "--index-only", action="store_true", help="rebuild the explorer without collecting"
    )
    args = parser.parse_args(argv)

    if args.index_only:
        index.build()
        return 0

    systems = [name.strip() for name in args.system.split(",") if name.strip()]
    systems = systems or list(ALL_SYSTEMS)
    phases = [name.strip() for name in args.phase.split(",") if name.strip()]
    unknown = [name for name in phases if name not in PHASES]
    if unknown:
        print(f"error: unknown phases: {', '.join(unknown)}", file=sys.stderr)
        return 2
    rounds = (
        [int(value) for value in args.rounds.split(",") if value.strip()]
        if args.rounds
        else round_counts()
    )

    medians = read_medians(CSV_PATH)
    try:
        capture.preflight()
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if not args.no_build:
        build_profiling_binary()
    if not BINARY.exists():
        print(f"error: missing {BINARY}", file=sys.stderr)
        return 1

    points: list[tuple[str, str, int]] = []
    for system in systems:
        for phase in phases:
            if phase == "setup" and system not in SETUP_SYSTEMS:
                continue
            for value in rounds:
                points.append((system, phase, value))

    collected = 0
    skipped = 0
    for position, (system, phase, value) in enumerate(points, start=1):
        out = ROOT / "results" / "profiles" / system / phase / f"r{value}"
        if (out / "chart.svg").exists() and not args.force:
            skipped += 1
            print(f"[{position}/{len(points)}] skip {system} {phase} r={value}", flush=True)
            continue

        median_ns = medians.get((system, phase, value), 0)
        if median_ns > 0:
            repeat = round(args.target_seconds * 1e9 / median_ns)
            repeat = max(1, min(args.max_repeat, repeat))
        else:
            repeat = 1

        print(
            f"[{position}/{len(points)}] {system} {phase} r={value} "
            f"repeat={repeat} (~{repeat * max(median_ns, 1) / 1e9:.2f}s)",
            flush=True,
        )
        try:
            capture.capture(system, value, phase, repeat, args.warmup)
        except (RuntimeError, subprocess.CalledProcessError, FileNotFoundError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        collected += 1

    print(f"collected {collected}, skipped {skipped}", flush=True)
    index.build()
    return 0
