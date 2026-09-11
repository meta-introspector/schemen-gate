# Benchmark receipts

This directory contains machine-readable results produced by checked-in
benchmark runners. A receipt records the source revision, implementation and
runner digests, environment, method, measurements, and exclusions needed to
interpret one run. It does not make the result portable across hardware,
software, shapes, dtypes, or execution backends.

The current Gate execution receipt is
[`results/gate_execution_numpy_cpu_20260911.json`](results/gate_execution_numpy_cpu_20260911.json).
Regenerate it with
[`scripts/benchmark_gate_execution.py`](../scripts/benchmark_gate_execution.py)
and interpret it through the repository's
[`performance evidence inventory`](../docs/PERFORMANCE.md).

