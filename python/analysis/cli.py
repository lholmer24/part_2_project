"""Command line entry point for benchmark plots."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import plots
from .benchmarks import METRICS, Summary, load_dataset

DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "results"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m analysis",
        description="Read a harness phase CSV and write the benchmark figures.",
    )
    parser.add_argument("csv", type=Path, help="path to the benchmark CSV")
    return parser


def main() -> int:
    csv_path = _parser().parse_args().csv

    try:
        dataset = load_dataset(csv_path)
        summary = Summary.from_dataset(dataset)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    prefix = csv_path.stem
    written = []

    for system in summary.systems:
        path = DEFAULT_OUTPUT / f"{prefix}_system_{system}.png"
        written.append(plots.plot_system(summary, system, path))

    for metric in METRICS:
        if not summary.for_metric(metric):
            print(f"skipping {metric}: no measurements", file=sys.stderr)
            continue
        path = DEFAULT_OUTPUT / f"{prefix}_metric_{metric}.png"
        written.append(plots.plot_metric(summary, metric, path))

    path = DEFAULT_OUTPUT / f"{prefix}_overview.png"
    written.append(plots.plot_overview(summary, path))

    for path in written:
        print(path)
    return 0
