#!/usr/bin/env python3
"""Build and test the Gate LibTorch API and Python execution layer."""

from __future__ import annotations

import argparse
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*command: str) -> None:
    print(f"+ {' '.join(command)}", flush=True)
    subprocess.run(command, cwd=ROOT, check=True)  # nosec B603


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-cuda", action="store_true")
    args = parser.parse_args()
    import torch

    if args.require_cuda and not torch.cuda.is_available():
        raise SystemExit("CUDA acceptance requested but NVIDIA CUDA is unavailable; no PASS")
    build = ROOT / "build" / "native"
    run(
        "cmake",
        "-S",
        str(ROOT / "native"),
        "-B",
        str(build),
        f"-DCMAKE_PREFIX_PATH={torch.utils.cmake_prefix_path}",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_TESTING=ON",
        f"-DSCHEMEN_GATE_REQUIRE_CUDA={'ON' if args.require_cuda else 'OFF'}",
    )
    run("cmake", "--build", str(build), "--parallel", "2")
    run("ctest", "--test-dir", str(build), "--output-on-failure", "--no-tests=error")
    run(sys.executable, "-m", "pytest", "-q", "-rs", "tests/test_torch_gate.py")
    print(
        f"PASS: Gate LibTorch/PyTorch {'CPU and CUDA' if args.require_cuda else 'CPU'} acceptance"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
