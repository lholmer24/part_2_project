#!/usr/bin/env python3
"""Clean collapsed stacks for the interactive flame-graph explorer.

Reads folded stacks, normalises every frame to the demangled function name
reported by perf, merges adjacent duplicates, aggregates equal stacks, and
writes:

  folded.txt   the cleaned stacks for inferno-flamegraph
  top.txt      inclusive sample counts per function

Frame names are left as they appear in the binary, so each chart frame can be
matched against the source. inferno-collapse-perf already removes top-level
argument lists and rewrites semicolons inside a name, because a semicolon
separates frames in the folded format.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path


def normalise(frame: str) -> str:
    """Return the function name that perf reports for one stack frame."""
    return frame.strip().replace("_[i]", "")


def clean(source: Path, outdir: Path) -> int:
    outdir.mkdir(parents=True, exist_ok=True)

    stacks: Counter[tuple[str, ...]] = Counter()
    inclusive: Counter[str] = Counter()
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
                label = normalise(frame)
                if not label:
                    continue
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

    with (outdir / "top.txt").open("w") as handle:
        handle.write(f"total weight: {samples}\n")
        handle.write(f"distinct stacks: {len(stacks)}\n")
        handle.write(f"distinct functions: {len(inclusive)}\n\n")
        for label, count in inclusive.most_common():
            handle.write(f"{100.0 * count / samples:6.2f}%  {count:7d}  {label}\n")

    return samples
