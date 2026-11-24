"""Plot aggregated benchmark results on log-log axes."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.axes import Axes  # noqa: E402
from matplotlib.ticker import NullFormatter, NullLocator  # noqa: E402

from .benchmarks import METRICS, SIZE_METRIC, Point, Summary

SYSTEM_LABELS = {
    "groth16": "Groth16",
    "plonk": "PLONK",
    "bulletproofs": "Bulletproofs",
    "stark": "STARK",
    "halo2": "Halo2",
    "spartan": "Spartan",
}

METRIC_LABELS = {
    "setup": "Setup time",
    "prove": "Prove time",
    "verify": "Verify time",
    "proof_size": "Proof size",
}

METRIC_UNITS = {
    "setup": "ns",
    "prove": "ns",
    "verify": "ns",
    "proof_size": "B",
}

_SYSTEM_STYLES = {
    "groth16": ("#1f77b4", "o"),
    "plonk": ("#ff7f0e", "s"),
    "halo2": ("#2ca02c", "^"),
    "bulletproofs": ("#d62728", "D"),
    "spartan": ("#9467bd", "v"),
    "stark": ("#8c564b", "P"),
}

_METRIC_STYLES = {
    "setup": ("#1f77b4", "o"),
    "prove": ("#ff7f0e", "s"),
    "verify": ("#2ca02c", "^"),
    "proof_size": ("#d62728", "D"),
}

_FALLBACK_STYLES = (
    ("#17becf", "X"),
    ("#bcbd22", "<"),
    ("#7f7f7f", ">"),
    ("#e377c2", "h"),
)


def system_label(system: str) -> str:
    return SYSTEM_LABELS.get(system, system)


def system_style(system: str, index: int = 0) -> tuple[str, str]:
    if system in _SYSTEM_STYLES:
        return _SYSTEM_STYLES[system]
    return _FALLBACK_STYLES[index % len(_FALLBACK_STYLES)]


def format_value(metric: str, value: float) -> str:
    """Format a measurement with a readable unit."""

    if metric == SIZE_METRIC:
        if value >= 1e6:
            return f"{value / 1e6:.3g} MB"
        if value >= 1e3:
            return f"{value / 1e3:.3g} kB"
        return f"{value:.3g} B"

    if value >= 1e9:
        return f"{value / 1e9:.3g} s"
    if value >= 1e6:
        return f"{value / 1e6:.3g} ms"
    if value >= 1e3:
        return f"{value / 1e3:.3g} µs"
    return f"{value:.3g} ns"


def round_tick_labels(rounds: list[int]) -> list[str]:
    """Label powers of two as ``2^k``; leave other values in decimal."""

    labels = []
    for rounds_value in rounds:
        exponent = rounds_value.bit_length() - 1
        if (1 << exponent) == rounds_value:
            labels.append(rf"$2^{{{exponent}}}$")
        else:
            labels.append(str(rounds_value))
    return labels


def _style_axes(
    ax: Axes, rounds: list[int], *, ylabel: str, title: str
) -> None:
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(rounds)
    ax.set_xticklabels(round_tick_labels(rounds), fontsize=8)
    ax.xaxis.set_minor_locator(NullLocator())
    ax.xaxis.set_minor_formatter(NullFormatter())

    low, high = min(rounds), max(rounds)
    ax.set_xlim(low / 3.5, high * 3.5)
    ax.set_xlabel("round count")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True, which="major", linestyle="--", linewidth=0.5, alpha=0.6)
    ax.grid(True, which="minor", axis="y", linestyle=":", linewidth=0.4, alpha=0.35)


@dataclass(frozen=True)
class _Endpoint:
    point: Point
    metric: str
    color: str


def _margin_y(ax: Axes, fraction: float = 0.08) -> None:
    low, high = ax.get_ylim()
    span = math.log10(high) - math.log10(low)
    ax.set_ylim(
        10 ** (math.log10(low) - span * fraction),
        10 ** (math.log10(high) + span * fraction),
    )


def _place_column(
    ax: Axes, entries: list[_Endpoint], alignment: str, dx: float
) -> None:
    """Place one column of labels, nudging them apart in display space."""

    if not entries:
        return
    fig = ax.figure
    measured = []
    for entry in entries:
        _, display_y = ax.transData.transform(
            (entry.point.rounds, entry.point.mean)
        )
        measured.append((entry, display_y))
    measured.sort(key=lambda item: item[1], reverse=True)

    gap = 12 * fig.dpi / 72
    adjusted: list[float] = []
    for _, display_y in measured:
        if adjusted:
            display_y = min(display_y, adjusted[-1] - gap)
        adjusted.append(display_y)

    shift = (sum(y for _, y in measured) - sum(adjusted)) / len(measured)
    adjusted = [display_y + shift for display_y in adjusted]

    for (entry, desired), display_y in zip(measured, adjusted):
        delta_points = (display_y - desired) * 72 / fig.dpi
        ax.annotate(
            format_value(entry.metric, entry.point.mean),
            (entry.point.rounds, entry.point.mean),
            xytext=(dx, delta_points),
            textcoords="offset points",
            ha=alignment,
            va="center",
            fontsize=7,
            color=entry.color,
            bbox={
                "boxstyle": "round,pad=0.15",
                "fc": "white",
                "ec": "none",
                "alpha": 0.9,
            },
            arrowprops={
                "arrowstyle": "-",
                "color": entry.color,
                "linewidth": 0.7,
                "alpha": 0.7,
                "shrinkA": 2,
                "shrinkB": 3,
                "connectionstyle": "angle,angleA=90,angleB=0,rad=0",
            },
        )


def _annotate_endpoints(ax: Axes, entries: list[_Endpoint]) -> None:
    """Write each measured value beside its first and last point."""

    if not entries:
        return
    low_round = min(entry.point.rounds for entry in entries)
    high_round = max(entry.point.rounds for entry in entries)
    groups: list[tuple[list[_Endpoint], str, float]] = [
        ([entry for entry in entries if entry.point.rounds == low_round], "right", -10)
    ]
    if high_round != low_round:
        groups.append(
            (
                [entry for entry in entries if entry.point.rounds == high_round],
                "left",
                10,
            )
        )
    for group, alignment, dx in groups:
        _place_column(ax, group, alignment, dx)


def _plot_series(
    ax: Axes,
    points: tuple[Point, ...],
    *,
    metric: str,
    label: str,
    color: str,
    marker: str,
) -> list[_Endpoint]:
    xs = [point.rounds for point in points]
    ys = [point.mean for point in points]
    errors = [point.stddev for point in points]
    ax.errorbar(
        xs,
        ys,
        yerr=errors,
        label=label,
        color=color,
        marker=marker,
        markersize=5,
        linewidth=1.4,
        capsize=2.5,
        elinewidth=0.8,
    )
    return [
        _Endpoint(point=point, metric=metric, color=color) for point in points
    ]


def _save(fig: plt.Figure, output_path: Path, dpi: int) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=dpi, bbox_inches="tight")
    plt.close(fig)
    return output_path


def plot_system(
    summary: Summary, system: str, output_path: Path, *, dpi: int = 200
) -> Path:
    """Plot setup, prove, verify and proof size for one system."""

    series = summary.for_system(system)
    if not series:
        raise ValueError(f"no measurements for system {system!r}")

    rounds = sorted({point.rounds for points in series.values() for point in points})
    fig, ax = plt.subplots(figsize=(9.0, 5.5))

    endpoints: list[_Endpoint] = []
    for metric, points in series.items():
        color, marker = _METRIC_STYLES[metric]
        endpoints.extend(
            _plot_series(
                ax,
                points,
                metric=metric,
                label=f"{METRIC_LABELS[metric]} ({METRIC_UNITS[metric]})",
                color=color,
                marker=marker,
            )
        )

    _style_axes(
        ax,
        rounds,
        ylabel="measured value (log scale; time in ns, size in bytes)",
        title=f"{system_label(system)}: MiMC preimage benchmark",
    )
    _margin_y(ax)
    ax.legend(loc="best", fontsize=8, framealpha=0.9)
    fig.tight_layout()
    fig.canvas.draw()
    _annotate_endpoints(ax, endpoints)
    return _save(fig, output_path, dpi)


def _draw_metric_axis(
    ax: Axes,
    summary: Summary,
    metric: str,
    *,
    legend_fontsize: float = 8,
) -> list[_Endpoint]:
    series = summary.for_metric(metric)
    if not series:
        raise ValueError(f"no measurements for metric {metric!r}")

    rounds = sorted({point.rounds for points in series.values() for point in points})
    endpoints: list[_Endpoint] = []
    for index, (system, points) in enumerate(series.items()):
        color, marker = system_style(system, index)
        endpoints.extend(
            _plot_series(
                ax,
                points,
                metric=metric,
                label=system_label(system),
                color=color,
                marker=marker,
            )
        )

    _style_axes(
        ax,
        rounds,
        ylabel=f"{METRIC_LABELS[metric].lower()} ({METRIC_UNITS[metric]})",
        title=f"MiMC {METRIC_LABELS[metric].lower()} by system",
    )
    _margin_y(ax)
    ax.legend(loc="best", fontsize=legend_fontsize, framealpha=0.9)
    return endpoints


def plot_metric(
    summary: Summary, metric: str, output_path: Path, *, dpi: int = 200
) -> Path:
    """Plot one measured value across every system that has it."""

    fig, ax = plt.subplots(figsize=(9.0, 5.5))
    endpoints = _draw_metric_axis(ax, summary, metric)
    fig.tight_layout()
    fig.canvas.draw()
    _annotate_endpoints(ax, endpoints)
    return _save(fig, output_path, dpi)


def plot_overview(summary: Summary, output_path: Path, *, dpi: int = 200) -> Path:
    """Plot the four metric figures together in a 2x2 grid."""

    selected = [metric for metric in METRICS if summary.for_metric(metric)]
    if not selected:
        raise ValueError("no metrics have measurements")

    fig, grid = plt.subplots(2, 2, figsize=(14.0, 10.0))
    axes = list(grid.flat)
    drawn: list[tuple[Axes, list[_Endpoint]]] = []
    for ax, metric in zip(axes, selected):
        drawn.append((ax, _draw_metric_axis(ax, summary, metric, legend_fontsize=7)))
    for ax in axes[len(selected) :]:
        ax.set_axis_off()

    fig.suptitle("MiMC benchmark metrics", fontsize=14)
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    fig.canvas.draw()
    for ax, endpoints in drawn:
        _annotate_endpoints(ax, endpoints)
    return _save(fig, output_path, dpi)

