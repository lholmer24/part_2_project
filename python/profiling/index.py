#!/usr/bin/env python3
"""Build the manifest and the interactive index page from the profile tree.

The tree is results/profiles/<system>/<phase>/r<rounds>/chart.svg. Each point
contributes its SVG path, intrinsic height, measured time and sample count to
the embedded manifest.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "results" / "profiles"
TEMPLATE = Path(__file__).with_name("index_template.html")
SYSTEM_ORDER = ["groth16", "plonk", "bulletproofs", "stark", "halo2", "spartan"]
PHASE_ORDER = ["setup", "prove", "verify"]


def provenance(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        key, _, value = line.partition(": ")
        if key:
            values[key.strip()] = value.strip()
    return values


def svg_height(path: Path) -> int:
    text = path.read_text(errors="replace")[:2000]
    match = re.search(r'<svg[^>]*height="(\d+)"', text)
    return int(match.group(1)) if match else 360


def build() -> None:
    PROFILES.mkdir(parents=True, exist_ok=True)
    systems = []
    for system_dir in sorted(path for path in PROFILES.iterdir() if path.is_dir()):
        phases = []
        field = ""
        for phase_dir in sorted(path for path in system_dir.iterdir() if path.is_dir()):
            points = []
            for point_dir in sorted(phase_dir.iterdir()):
                svg = point_dir / "chart.svg"
                if not svg.is_file() or not point_dir.name.startswith("r"):
                    continue
                try:
                    rounds = int(point_dir.name[1:])
                except ValueError:
                    continue
                info = provenance(point_dir / "provenance.txt")
                field = field or info.get("field", "")
                points.append(
                    {
                        "rounds": rounds,
                        "samples": int(info.get("samples", 0)),
                        "per_call_ns": int(info.get("per_call_ns", 0)),
                        "svg": f"{system_dir.name}/{phase_dir.name}/{point_dir.name}/chart.svg",
                        "height": svg_height(svg),
                    }
                )
            if points:
                points.sort(key=lambda point: point["rounds"])
                phases.append({"name": phase_dir.name, "points": points})
        if not phases:
            continue
        phases.sort(key=lambda phase: PHASE_ORDER.index(phase["name"]))
        systems.append({"name": system_dir.name, "field": field, "phases": phases})

    systems.sort(
        key=lambda system: (
            SYSTEM_ORDER.index(system["name"])
            if system["name"] in SYSTEM_ORDER
            else len(SYSTEM_ORDER),
            system["name"],
        )
    )

    data = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "systems": systems,
    }

    (PROFILES / "manifest.json").write_text(json.dumps(data, indent=2) + "\n")
    (PROFILES / "index.html").write_text(
        TEMPLATE.read_text().replace("__DATA__", json.dumps(data, separators=(",", ":")))
    )

    points = sum(len(phase["points"]) for system in systems for phase in system["phases"])
    print(
        f"wrote {PROFILES / 'index.html'} "
        f"({len(systems)} systems, {points} points)"
    )
