"""Benchmark result parsing, summaries and plots.

Reads the raw phase CSV and the metadata sidecar written by the Rust harness,
then writes one log-log figure per system and one per measured value.
"""

from .benchmarks import (
    METRICS,
    Point,
    Record,
    Summary,
    load_dataset,
    read_csv,
    summarise,
)
from .plots import plot_metric, plot_overview, plot_system

__all__ = [
    "METRICS",
    "Point",
    "Record",
    "Summary",
    "load_dataset",
    "plot_metric",
    "plot_overview",
    "plot_system",
    "read_csv",
    "summarise",
]
