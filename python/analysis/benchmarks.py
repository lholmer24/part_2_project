"""Parse the harness phase CSV and aggregate samples.

The harness writes one row per timed sample. ``proof_size_bytes`` is present on
``prove`` rows only, so a proof-size summary reads its values from that phase.
"""

from __future__ import annotations

import csv
import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

TIME_PHASES = ("setup", "prove", "verify")
METRICS = ("setup", "prove", "verify", "proof_size")
SIZE_METRIC = "proof_size"

REQUIRED_COLUMNS = (
    "system",
    "field",
    "rounds",
    "phase",
    "sample",
    "time_ns",
    "proof_size_bytes",
)

REQUIRED_METADATA = ("build_profile",)


@dataclass(frozen=True)
class Record:
    """One timed sample from the harness CSV."""

    system: str
    field: str
    rounds: int
    phase: str
    sample: int
    time_ns: int
    proof_size_bytes: int | None


@dataclass(frozen=True)
class Point:
    """Aggregated samples for one system, metric and round count."""

    rounds: int
    mean: float
    stddev: float
    count: int


@dataclass(frozen=True)
class Dataset:
    """A parsed CSV file and its optional metadata sidecar."""

    path: Path
    records: tuple[Record, ...]
    metadata: Mapping[str, object] | None

    @property
    def systems(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(record.system for record in self.records))

    @property
    def fields(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(record.field for record in self.records))


def _parse_int(value: str, column: str, line: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"line {line}: {column} is not an integer: {value!r}") from exc


def read_csv(path: Path) -> tuple[Record, ...]:
    """Read and validate a harness phase CSV."""

    path = Path(path)
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        header = tuple(reader.fieldnames or ())
        if header != REQUIRED_COLUMNS:
            missing = [column for column in REQUIRED_COLUMNS if column not in header]
            extra = [column for column in header if column not in REQUIRED_COLUMNS]
            raise ValueError(
                f"{path}: unexpected CSV schema; missing={missing} extra={extra}"
            )

        records: list[Record] = []
        seen: set[tuple[str, int, str, int]] = set()
        for line, row in enumerate(reader, start=2):
            system = (row["system"] or "").strip()
            field = (row["field"] or "").strip()
            phase = (row["phase"] or "").strip()
            if not system or not field:
                raise ValueError(f"line {line}: system and field must not be empty")
            if phase not in TIME_PHASES:
                raise ValueError(f"line {line}: unknown phase {phase!r}")

            rounds = _parse_int(row["rounds"], "rounds", line)
            if rounds <= 0 or rounds & (rounds - 1):
                raise ValueError(
                    f"line {line}: rounds must be a positive power of two, got {rounds}"
                )
            sample = _parse_int(row["sample"], "sample", line)
            if sample < 0:
                raise ValueError(f"line {line}: sample must not be negative")
            time_ns = _parse_int(row["time_ns"], "time_ns", line)
            if time_ns <= 0:
                raise ValueError(f"line {line}: time_ns must be positive")

            size_text = (row["proof_size_bytes"] or "").strip()
            proof_size = (
                _parse_int(size_text, "proof_size_bytes", line) if size_text else None
            )
            if phase == "prove" and proof_size is None:
                raise ValueError(f"line {line}: prove rows need proof_size_bytes")
            if phase != "prove" and proof_size is not None:
                raise ValueError(
                    f"line {line}: proof_size_bytes belongs on prove rows only"
                )
            if proof_size is not None and proof_size <= 0:
                raise ValueError(f"line {line}: proof_size_bytes must be positive")

            key = (system, rounds, phase, sample)
            if key in seen:
                raise ValueError(f"line {line}: duplicate sample {key}")
            seen.add(key)

            records.append(
                Record(
                    system=system,
                    field=field,
                    rounds=rounds,
                    phase=phase,
                    sample=sample,
                    time_ns=time_ns,
                    proof_size_bytes=proof_size,
                )
            )

    if not records:
        raise ValueError(f"{path}: CSV has no data rows")
    return tuple(records)


def metadata_path(csv_path: Path) -> Path:
    """Return the sidecar path for ``benchmarks.csv`` or a similar name."""

    return Path(csv_path).with_suffix(".meta.json")


def read_metadata(csv_path: Path) -> Mapping[str, object] | None:
    """Load the metadata sidecar when it exists."""

    path = metadata_path(csv_path)
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as handle:
        metadata = json.load(handle)
    if not isinstance(metadata, dict):
        raise ValueError(f"{path}: metadata must be a JSON object")

    missing = [key for key in REQUIRED_METADATA if key not in metadata]
    if missing:
        raise ValueError(f"{path}: metadata is missing {missing}")

    csv_file = metadata.get("csv_file")
    if csv_file is not None and csv_file != Path(csv_path).name:
        raise ValueError(
            f"{path}: csv_file is {csv_file!r}, expected {Path(csv_path).name!r}"
        )
    return metadata


def load_dataset(csv_path: Path, *, require_release: bool = True) -> Dataset:
    """Read a CSV and its sidecar, rejecting debug-build measurements."""

    csv_path = Path(csv_path)
    metadata = read_metadata(csv_path)
    if require_release and metadata is not None:
        profile = metadata.get("build_profile")
        if profile != "release":
            raise ValueError(
                f"{metadata_path(csv_path)}: build_profile is {profile!r}, "
                "expected 'release'"
            )

    records = read_csv(csv_path)

    if metadata is not None:
        systems = metadata.get("systems")
        if systems is not None:
            unknown = sorted({record.system for record in records} - set(systems))
            if unknown:
                raise ValueError(
                    f"{metadata_path(csv_path)}: systems {unknown} are not listed"
                )
        rounds = metadata.get("rounds")
        if rounds is not None:
            unknown = sorted({record.rounds for record in records} - set(rounds))
            if unknown:
                raise ValueError(
                    f"{metadata_path(csv_path)}: rounds {unknown} are not listed"
                )

    return Dataset(path=csv_path, records=records, metadata=metadata)


def _values(records: Iterable[Record], metric: str) -> Iterable[tuple[str, int, float]]:
    if metric in TIME_PHASES:
        for record in records:
            if record.phase == metric:
                yield record.system, record.rounds, float(record.time_ns)
    elif metric == SIZE_METRIC:
        for record in records:
            if record.phase == "prove":
                if record.proof_size_bytes is None:
                    raise ValueError("prove row has no proof size")
                yield record.system, record.rounds, float(record.proof_size_bytes)
    else:
        raise ValueError(f"unknown metric {metric!r}; expected one of {METRICS}")


def summarise(
    records: Iterable[Record], metric: str, *, ddof: int = 1
) -> dict[str, tuple[Point, ...]]:
    """Group samples by system and round count, then take the mean and stddev."""

    grouped: dict[str, dict[int, list[float]]] = {}
    for system, rounds, value in _values(records, metric):
        grouped.setdefault(system, {}).setdefault(rounds, []).append(value)

    summary: dict[str, tuple[Point, ...]] = {}
    for system, by_round in grouped.items():
        points = []
        for rounds, values in sorted(by_round.items()):
            mean = statistics.fmean(values)
            stddev = statistics.stdev(values) if len(values) > ddof else 0.0
            points.append(
                Point(rounds=rounds, mean=mean, stddev=stddev, count=len(values))
            )
        summary[system] = tuple(points)
    return summary


class Summary:
    """Aggregated means and standard deviations for every metric."""

    def __init__(self, by_metric: Mapping[str, Mapping[str, tuple[Point, ...]]]):
        self._by_metric = {
            metric: dict(by_system) for metric, by_system in by_metric.items()
        }
        self.systems = tuple(
            dict.fromkeys(
                system
                for metric in METRICS
                for system in self._by_metric.get(metric, {})
            )
        )

    @classmethod
    def from_records(cls, records: Iterable[Record], *, ddof: int = 1) -> "Summary":
        records = tuple(records)
        return cls(
            {metric: summarise(records, metric, ddof=ddof) for metric in METRICS}
        )

    @classmethod
    def from_dataset(cls, dataset: Dataset, *, ddof: int = 1) -> "Summary":
        return cls.from_records(dataset.records, ddof=ddof)

    def for_system(self, system: str) -> dict[str, tuple[Point, ...]]:
        """Return the metrics a system has data for, in metric order."""

        return {
            metric: self._by_metric[metric][system]
            for metric in METRICS
            if system in self._by_metric.get(metric, {})
        }

    def for_metric(self, metric: str) -> dict[str, tuple[Point, ...]]:
        """Return every system with data for one metric, in name order."""

        if metric not in METRICS:
            raise ValueError(f"unknown metric {metric!r}; expected one of {METRICS}")
        return dict(sorted(self._by_metric.get(metric, {}).items()))

    def systems_for_metric(self, metric: str) -> tuple[str, ...]:
        return tuple(self.for_metric(metric))

    def metrics_for_system(self, system: str) -> tuple[str, ...]:
        return tuple(self.for_system(system))
