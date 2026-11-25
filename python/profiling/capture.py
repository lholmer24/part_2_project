"""Capture one harness phase under perf and render a flame graph."""

from __future__ import annotations

import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from .clean import clean

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "results" / "profiles"
BINARY = ROOT / "target" / "profiling" / "profile_phase"
REQUIRED_TOOLS = ("perf", "inferno-collapse-perf", "inferno-flamegraph")


def preflight() -> None:
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        raise RuntimeError(
            "missing tools: "
            + ", ".join(missing)
            + " (install perf and cargo install inferno --version 0.11.21 --locked)"
        )
    probe = subprocess.run(
        ["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if probe.returncode != 0:
        raise RuntimeError(
            "passwordless sudo is required for callchain sampling at perf_event_paranoid=2"
        )


def fmt_time(ns: int, suffix: str) -> str:
    if ns >= 1_000_000_000:
        return f"{ns / 1e9:.2f} s {suffix}"
    if ns >= 1_000_000:
        return f"{ns / 1e6:.1f} ms {suffix}"
    if ns >= 1_000:
        return f"{ns / 1e3:.0f} µs {suffix}"
    return f"{ns} ns {suffix}"


def _wait_ready(driver: subprocess.Popen, out_path: Path, err_path: Path) -> None:
    deadline = time.monotonic() + 3600
    while True:
        if out_path.exists() and "READY" in out_path.read_text(errors="replace"):
            return
        if driver.poll() is not None:
            raise RuntimeError(
                "driver exited before READY:\n" + err_path.read_text(errors="replace")
            )
        if time.monotonic() > deadline:
            raise RuntimeError("timed out waiting for READY")
        time.sleep(0.1)


def _parse_provenance(driver_out: str, driver_err: str) -> tuple[int, int, str]:
    match = re.search(r"DONE total_ns=(\d+) per_call_ns=(\d+)", driver_out)
    if not match:
        raise RuntimeError("driver did not report a timing line")
    field = re.search(r"^system \S+ field (\S+) ", driver_err, re.MULTILINE)
    return int(match.group(1)), int(match.group(2)), field.group(1) if field else ""


def capture(
    system: str,
    rounds: int,
    phase: str,
    repeat: int,
    warmup: int = 1,
) -> Path:
    outdir = PROFILES / system / phase / f"r{rounds}"
    outdir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=PROFILES))
    go = tmp / "go"
    driver = None
    perf = None

    try:
        with (tmp / "driver.out").open("w") as out, (tmp / "driver.err").open("w") as err:
            driver = subprocess.Popen(
                [
                    str(BINARY),
                    "--system",
                    system,
                    "--rounds",
                    str(rounds),
                    "--phase",
                    phase,
                    "--repeat",
                    str(repeat),
                    "--warmup",
                    str(warmup),
                    "--go-file",
                    str(go),
                ],
                stdout=out,
                stderr=err,
            )
        _wait_ready(driver, tmp / "driver.out", tmp / "driver.err")

        with (tmp / "perf.log").open("w") as log:
            perf = subprocess.Popen(
                [
                    "sudo",
                    "-n",
                    "perf",
                    "record",
                    "-q",
                    "-o",
                    str(tmp / "perf.data"),
                    "-p",
                    str(driver.pid),
                    "-g",
                    "--call-graph",
                    "fp,127",
                    "-F",
                    "999",
                    "-e",
                    "cpu-clock:u",
                ],
                stdout=subprocess.DEVNULL,
                stderr=log,
            )
        time.sleep(1)
        if perf.poll() is not None:
            raise RuntimeError("perf failed to attach:\n" + (tmp / "perf.log").read_text())
        go.touch()
        driver.wait()
        perf.send_signal(signal.SIGINT)
        try:
            perf.wait(timeout=60)
        except subprocess.TimeoutExpired:
            perf.kill()
            perf.wait()

        if not (tmp / "perf.data").is_file() or (tmp / "perf.data").stat().st_size == 0:
            raise RuntimeError("perf produced no data")

        with (tmp / "perf.script").open("w") as out, (tmp / "perf.script.err").open("w") as err:
            subprocess.run(
                ["sudo", "-n", "perf", "script", "-i", str(tmp / "perf.data")],
                check=True,
                stdout=out,
                stderr=err,
            )
        with (tmp / "perf.script").open() as stdin, (tmp / "folded.raw").open("w") as out:
            subprocess.run(["inferno-collapse-perf"], check=True, stdin=stdin, stdout=out)

        weight = clean(tmp / "folded.raw", outdir)
        driver_out = (tmp / "driver.out").read_text(errors="replace")
        driver_err = (tmp / "driver.err").read_text(errors="replace")
        total_ns, per_call_ns, field = _parse_provenance(driver_out, driver_err)
        samples = sum(
            1
            for line in (tmp / "perf.script").read_text(errors="replace").splitlines()
            if re.match(r"^profile_phase\s+\d+\s+[\d.]+:", line)
        )

        title = f"{system} {phase} at r = {rounds}"
        subtitle = (
            f"{samples} samples | {weight / 1e6:.1f} ms weighted | "
            f"{fmt_time(per_call_ns, 'per call')}"
        )
        with (outdir / "chart.svg").open("w") as out:
            subprocess.run(
                [
                    "inferno-flamegraph",
                    "--deterministic",
                    "--width",
                    "2000",
                    "--height",
                    "18",
                    "--fontsize",
                    "14",
                    "--minwidth",
                    "1",
                    "--bgcolors",
                    "#f5f5f5",
                    "--title",
                    title,
                    "--subtitle",
                    subtitle,
                    str(outdir / "folded.txt"),
                ],
                cwd=tmp,
                check=True,
                stdout=out,
            )

        shutil.copy(tmp / "driver.out", outdir / "driver.out")
        shutil.copy(tmp / "driver.err", outdir / "driver.err")
        governor_path = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        governor = governor_path.read_text().strip() if governor_path.exists() else "unknown"
        host = subprocess.run(
            ["uname", "-srm"], capture_output=True, text=True, check=False
        ).stdout.strip()
        perf_version = subprocess.run(
            ["perf", "--version"], capture_output=True, text=True, check=False
        ).stdout.strip()
        (outdir / "provenance.txt").write_text(
            "\n".join(
                [
                    f"captured: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
                    f"host: {host}",
                    f"governor: {governor}",
                    f"command: profile_phase --system {system} --rounds {rounds} --phase {phase} --repeat {repeat} --warmup {warmup}",
                    f"field: {field}",
                    "build: cargo --profile profiling, debug=2, RUSTFLAGS=-Cforce-frame-pointers=y",
                    f"perf: {perf_version}",
                    f"samples: {samples}",
                    f"weight: {weight}",
                    f"per_call_ns: {per_call_ns}",
                    f"total_ns: {total_ns}",
                ]
            )
            + "\n"
        )
        print(
            f"wrote {outdir / 'chart.svg'} "
            f"({samples} samples, {weight / 1e6:.1f} ms weighted)",
            flush=True,
        )
        return outdir
    finally:
        if driver is not None and driver.poll() is None:
            driver.kill()
            driver.wait()
        if perf is not None and perf.poll() is None:
            perf.kill()
            perf.wait()
        shutil.rmtree(tmp, ignore_errors=True)
