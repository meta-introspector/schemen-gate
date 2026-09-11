#!/usr/bin/env python3
"""Benchmark the fail-closed NumPy Gate against a dense square projection.

This is a component benchmark. It measures the public ``GateMask.apply`` API
after mask authorization has already completed; it does not measure PKI,
grant verification, model serving, PyTorch/CUDA, or end-to-end inference.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess  # nosec B404 - fixed local Git inspection only
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

import numpy as np

from schemen_gate import GateMask

ROOT = Path(__file__).resolve().parents[1]
THREAD_ENVIRONMENT = (
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
    "MKL_NUM_THREADS",
)


@dataclass(frozen=True)
class Timing:
    median_microseconds: float
    minimum_microseconds: float
    maximum_microseconds: float
    samples: int
    iterations_per_sample: int


def _time_batch(function: Callable[[], object], iterations: int) -> float:
    start = time.perf_counter_ns()
    for _ in range(iterations):
        function()
    return (time.perf_counter_ns() - start) / 1_000_000_000


def _benchmark(
    function: Callable[[], object],
    *,
    samples: int,
    minimum_sample_seconds: float,
) -> Timing:
    for _ in range(5):
        function()

    iterations = 1
    while _time_batch(function, iterations) < minimum_sample_seconds:
        iterations *= 2
        if iterations > 1_048_576:
            break

    observations = [
        _time_batch(function, iterations) * 1_000_000 / iterations for _ in range(samples)
    ]
    return Timing(
        median_microseconds=statistics.median(observations),
        minimum_microseconds=min(observations),
        maximum_microseconds=max(observations),
        samples=samples,
        iterations_per_sample=iterations,
    )


def _git_metadata() -> dict[str, object]:
    try:
        revision = subprocess.check_output(  # nosec B603 B607
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        status = subprocess.check_output(  # nosec B603 B607
            ["git", "-C", str(ROOT), "status", "--porcelain"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return {"revision": revision, "tree_clean": not bool(status)}
    except (FileNotFoundError, subprocess.CalledProcessError):
        return {"revision": None, "tree_clean": None}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _blas_name() -> str | None:
    try:
        build = np.__config__.CONFIG.get("Build Dependencies", {})
        blas = build.get("blas", {})
        name = blas.get("name")
        return str(name) if name else None
    except (AttributeError, TypeError):
        return None


def _measure_width(
    width: int,
    *,
    samples: int,
    minimum_sample_seconds: float,
    rng: np.random.Generator,
) -> dict[str, object]:
    gate = GateMask.from_indices(range(0, width, 2), n_dims=width)
    hidden = rng.standard_normal((1, width), dtype=np.float64)
    weights = rng.standard_normal((width, width), dtype=np.float64)

    gated = gate.apply(hidden)
    if gated.shape != hidden.shape or np.any(gated[..., 1::2] != 0.0):
        raise RuntimeError("Gate correctness control failed")
    if np.signbit(gated[..., 1::2]).any():
        raise RuntimeError("Gate positive-zero control failed")
    if (hidden @ weights).shape != hidden.shape:
        raise RuntimeError("projection shape control failed")

    gate_timing = _benchmark(
        lambda: gate.apply(hidden),
        samples=samples,
        minimum_sample_seconds=minimum_sample_seconds,
    )
    projection_timing = _benchmark(
        lambda: hidden @ weights,
        samples=samples,
        minimum_sample_seconds=minimum_sample_seconds,
    )
    ratio = gate_timing.median_microseconds / projection_timing.median_microseconds
    return {
        "width": width,
        "batch_vectors": 1,
        "dtype": "float64",
        "gate_selection_elements": width,
        "dense_projection_multiply_accumulates": width * width,
        "gate": asdict(gate_timing),
        "dense_square_projection": asdict(projection_timing),
        "gate_to_projection_ratio": ratio,
        "gate_overhead_percent_of_one_projection": ratio * 100.0,
    }


def _parse_widths(value: str) -> list[int]:
    try:
        widths = [int(item) for item in value.split(",")]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("widths must be comma-separated integers") from exc
    if not widths or any(width <= 0 for width in widths):
        raise argparse.ArgumentTypeError("widths must contain positive integers")
    return widths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--widths", type=_parse_widths, default=[768, 4096])
    parser.add_argument("--samples", type=int, default=15)
    parser.add_argument("--minimum-sample-seconds", type=float, default=0.02)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.samples < 3:
        parser.error("--samples must be at least 3")
    if not 0.001 <= args.minimum_sample_seconds <= 5.0:
        parser.error("--minimum-sample-seconds must be between 0.001 and 5.0")

    rng = np.random.default_rng(20260911)
    result = {
        "schema": "schemen-gate-execution-benchmark/v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "scope": (
            "Fail-closed NumPy GateMask.apply forward execution after authorization, "
            "compared with one dense square projection on the same host."
        ),
        "exclusions": [
            "PKI and grant verification",
            "mask derivation",
            "backward pass",
            "PyTorch, C++, and CUDA",
            "end-to-end model inference",
        ],
        "method": {
            "clock": "time.perf_counter_ns",
            "warmup_calls": 5,
            "sample_statistic": "median of per-call batch timings",
            "minimum_sample_seconds": args.minimum_sample_seconds,
            "random_seed": 20260911,
            "projection": "one float64 row vector times one reused width-by-width matrix",
        },
        "environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "blas": _blas_name(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
            "thread_environment": {name: os.environ.get(name) for name in THREAD_ENVIRONMENT},
        },
        "source": {
            "git": _git_metadata(),
            "benchmark_script_sha256": _sha256(Path(__file__)),
            "gate_implementation_sha256": _sha256(ROOT / "src/schemen_gate/_mask.py"),
        },
        "measurements": [
            _measure_width(
                width,
                samples=args.samples,
                minimum_sample_seconds=args.minimum_sample_seconds,
                rng=rng,
            )
            for width in args.widths
        ],
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(encoded)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
