# Performance evidence and claim boundaries

**Evidence reviewed:** 2026-09-11
**Core result:** an already-authorized activation Gate is linear in the number
of activation elements. Measured latency remains shape-, implementation-, and
hardware-dependent.

This inventory separates the small binary execution primitive from model
consolidation, keyed-basis experiments, and experimental Hydra scheduling.
Those surfaces answer different performance questions and their numbers are
not interchangeable.

## Gate execution cost

For `M` vectors whose gated axis has width `d`, the forward Gate performs one
selection per element:

\[
T_{gate}=\Theta(Md).
\]

Around a Transformer FFN boundary, the adjacent projections perform
approximately `M * d_in * d` and `M * d * d_out` multiply-accumulates. If all
widths grow proportionally with `d`, their cost is $\Theta(Md^2)$. The
arithmetic-work ratio therefore falls like $\Theta(1/d)$. This statement does
not assign a latency ratio: kernel launches, interpreter overhead, allocation,
memory bandwidth, dtype, vector count, fusion, and the surrounding graph can
dominate the small linear operation.

The current implementation uses boolean selection rather than multiplication:

```text
where(mask, hidden, positive_zero)
```

This preserves the fail-closed numerical contract: an excluded NaN, infinity,
or negative zero becomes positive zero. A historical `hidden * mask`
microbenchmark does not measure this current implementation.

Mask derivation, grant verification, PKI, replay checks, model lookup, and
receipt persistence are separate operations. An embedding application can
resolve and retain an authorized mask for its permitted lifetime; it should
measure those authority operations at its actual request boundary.

## Authority placement and system cost

An output-control design can run complete inference, classify the result, and
then withhold or sequester it. For the same authority decision, an internal Gate
places denial earlier: excluded activation state is zeroed before the following
projection and before it can contribute to an output. The relevant system
denominator can therefore include an avoided post-inference classification,
storage, review, or sequestration path as well as the Gate operation itself.

No retained benchmark in this repository measures that end-to-end comparison,
so the current evidence does not assign a latency, throughput, memory, or cost
saving to it. Internal gating also does not by itself reduce the nominal work
of an unfused dense projection over the zeroed coordinates. Compute savings
require mask folding, physical extraction, a compatible structured sparse
kernel, or fusion with the surrounding projection. Output classification can
still serve policy questions other than the Gate's authority decision.

## Current component benchmark

The reproducible runner is
[`scripts/benchmark_gate_execution.py`](../scripts/benchmark_gate_execution.py).
The retained result is
[`benchmarks/results/gate_execution_numpy_cpu_20260911.json`](../benchmarks/results/gate_execution_numpy_cpu_20260911.json).
It identifies clean source revision `f00e601471d0f9ebe8ece681be530f5ca79e19f0`,
hashes the benchmark and Gate implementation, and records the environment and
complete timing range.

```bash
PYTHONPATH=src \
VECLIB_MAXIMUM_THREADS=1 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
python3 scripts/benchmark_gate_execution.py \
  --widths 768,4096,12288 \
  --samples 15 \
  --minimum-sample-seconds 0.05 \
  --output benchmarks/results/gate_execution_numpy_cpu_20260911.json
```

The host was arm64 macOS with Python 3.14.6, NumPy 2.4.6, Accelerate BLAS, and
18 reported logical CPUs. All named BLAS thread controls were fixed to one.
Each row uses one float64 activation vector and one reused float64 square
matrix. Five warmup calls are excluded. Each retained sample is a batch of
calls lasting at least 50 ms; the table reports the median per call across 15
samples.

| Width `d` | Gate median (range) | Projection median (range) | Gate / projection |
|---:|---:|---:|---:|
| 768 | 1.502 us (1.469–1.635) | 7.169 us (6.983–8.299) | 20.955% |
| 4,096 | 3.174 us (3.141–3.442) | 1,415.387 us (1,321.023–1,880.276) | 0.224% |
| 12,288 | 7.762 us (7.557–10.034) | 11,806.104 us (10,900.318–15,997.010) | 0.066% |

This component result supports the linear-versus-quadratic account and shows
why it must not be paraphrased as universally negligible overhead. It does not
measure a complete model or the optional Torch path. The C++ interface calls
the same ATen selection operator as the Python Torch layer; source parity is
not performance evidence. No checked-in PyTorch CPU, CUDA, C++/LibTorch,
backward, compiled, or fused-kernel timing receipt exists yet.

## Model and deployment results in this repository

### DistilBERT R8 service consolidation

The strongest retained model-level systems result is the full SST-2 R8 T4
benchmark in
[`distilbert_service_consolidation_20260821T135530_707107Z.json`](../research/cdp/experiments/results/distilbert_service_consolidation_20260821T135530_707107Z.json).
It is a documented public evidence export of a clean historical run under a
private companion authorization harness.

Eight complete services used 1,071,280,160 checkpoint bytes and 1,102,979,072
resident CUDA parameter-and-buffer bytes. One frozen shared backbone with eight
zero-initialized private adapter slots used 151,643,168 and 156,168,192 bytes,
respectively: about 7.06x lower in both denominators. Both conditions scored
91.055% utility. In one serial request stream, the shared condition measured
1,579.35 samples/s versus 1,593.19 for the eight-service condition, a
descriptive ratio of 0.9913. The run has no concurrency or statistical-parity
claim.

The same study deliberately tested naive post-hoc one-eighth FFN slicing. Its
utility fell to 67.661%. Physical extraction preserved that sliced function
within the declared fp16 tolerance and raised its throughput from 1,584.62 to
2,872.43 samples/s, a 1.813x speedup. This supports extraction of an already
narrowed function. It rejects the stronger claim that naive slicing preserves
the original dense model's utility.

### Formative DistilBERT deployment smoke

[`distilbert_deployment_20260806_103232.json`](../research/cdp/experiments/results/distilbert_deployment_20260806_103232.json)
records four-way state-dict arithmetic: 1,062,014,092 bytes for four copies
versus 265,503,523 bytes for one gated copy, exactly 4.0x. Its CPU timing used
only one batch of four samples and reported 259.01 versus 148.95 samples/s.
That timing is a smoke observation, not a throughput claim. The paper promotes
the storage arithmetic only. Historical 3.6x GPU-memory and 2.69x throughput
figures are explicitly withheld pending a hardware-matched rerun; see the
[`experiment data inventory`](../research/cdp/docs/experiment-data-inventory.md#deployment-savings-distilbert).

### Keyed-basis placement and batching

The retained `true_multiplexing` and `mux_scaling` artifacts measure whole-model
permutation gathers and batching. They do not isolate the binary Gate
primitive. The corrected R4 run recorded 29.3% overhead versus one unpermuted
base batch and 1.2x speedup versus four serial addressed calls. The R-scaling
run recorded 1.71x–3.59x speedup over serial at R4–R8, declining to 1.39x at
R128. A separate R128 timing record measured 93.8% overhead versus an equal-size
unpermuted batch, 2.9x versus serial shared-weight calls, and 11.1x versus its
serial-plus-conjugation estimate.

These results show that batching can amortize repeated calls while Python-level
gathers can remain expensive. The operation-count estimate of about `1/d` did
not predict observed latency. The paper describes the R128 MPS result and its
confounds in the
[`keyed-basis performance section`](../research/cdp/paper/cdp.tex).

## Hydra performance is experimental

Hydra is an experimental Transformer regime-lane architecture. Its complete
attention banks, private state, batching, and selector layout are much broader
than the binary Gate primitive. The current public record supports these
bounded performance observations:

- For Qwen3-4B R2 on one A100, the shared-backbone-plus-attention-bank artifact
  was 9,932,460,808 bytes versus a 16,089,964,000-byte two-checkpoint ceiling,
  38.27% smaller. Peak allocated GPU memory was 31.68% lower in that ordered
  process.
- Naive two-stream eager dispatch was slower in all nine matched
  topology/context cells. Ordinary shared, banked, and two-full-model controls
  all slowed, so the result rejects eager CUDA streams as a useful scheduler;
  it does not attribute the slowdown to the Gate.
- R4 row batching improved prefill from 214.75 to 160.32 ms at 64 tokens
  (1.339x) and from 204.34 to 156.36 ms at 256 tokens (1.307x). At 1,024 tokens
  it measured 380.44 versus 382.95 ms (0.993x), because the implementation
  still invoked private attention once per row.
- R8 and R16 persistent inventories were 33.866 and 61.999 GiB. At R16, a
  contiguous zero-copy half-roster view raised the tested median from 52.288
  to 62.058 real tokens/s (18.68%) and removed 0.548 GiB of transient peak
  allocation. Reordered rosters retain the gather path.

The exact scopes and failures are in
[`RESULTS_AND_CORRECTIONS.md`](../research/cdp/gated-transformer-regime-lanes/RESULTS_AND_CORRECTIONS.md)
and the
[`Hydra claim ledger`](../research/cdp/gated-transformer-regime-lanes/CLAIM_LEDGER.md).
These figures do not establish production scheduling, continuous batching,
tail latency, side-channel resistance, or universal GPU behavior.

## Historical and local records reviewed

The broader workspace and journal search found additional records. They are
retained here to prevent future copy from silently promoting them:

- The original `schemen` / `schemen-workspace` benchmark at assembly revision
  `bab00dd9051005ccf1360ceff2556060d529c64e` timed `hidden * mask` with NumPy.
  Its README rounded the Gate to under 3 us at `d=768`, under 5 us at 4,096,
  and under 10 us at 12,288, against about 200 us, 5 ms, and 50 ms square
  projections. The script survived, but the raw samples, hardware identity,
  Python/NumPy/BLAS versions, and run receipt did not. Its separate claim of
  less than 0.1% at `d=768` is inconsistent with its own rounded table. None of
  those numerical claims is current release evidence.
- Historical TinyLlama figures reported 4.00x disk, 3.99x GPU memory, and
  3.90x throughput at R4. Their sources are not shipped, so the current
  [`experiment inventory`](../research/cdp/docs/experiment-data-inventory.md)
  keeps them outside the paper evidence.
- `schemen-gate-whisper-hydra` revision `2245e673` contains an unmerged R4 CPU
  research result: 674.63 aggregate decoder tokens/s for hybrid execution,
  555.67 for serial Hydra, and 575.54 for four restricted full-replica
  controls. The paired hybrid/serial median speedup was 1.225x with a post-hoc
  bootstrap interval of 1.198–1.383x. Serialized tensor packages were 60.902%
  smaller and median fresh-process RSS was 24.260% lower than replicas. It is
  CPU-local, experimental, and absent from current public `main`, so the root
  README does not cite it as release evidence.
- A local grouped-Qwen follow-up recorded favorable prefill speedups while
  failing frozen bit-exactness, cached-decoder, and SFT-utility gates. Its
  working record is not committed to current public `main`; no claim from it is
  promoted here.
- The Substrate journal's 4.21x R8 one-matmul result compares one packed matrix
  call with eight small calls. It is a different `MultiEncoder` construction,
  not a measurement of `GateMask.apply`, and is excluded from Gate overhead.
- The source tree includes a VectorBridge microbenchmark and a planned fused
  multiplexing GPU runner. Neither has a retained claim-eligible result. The
  current vLLM and SGLang admission integrations likewise contain no retained
  performance benchmark.

## What can be said today

The supported performance claim for the core operation is precise: applying an
already-authorized Gate is linear in the gated activation size and introduces
no additional matrix multiplication. On the retained CPU component run, the
actual fail-closed NumPy API was 0.224% of one square projection at width 4,096
and 0.066% at width 12,288. At width 768 it was 20.95%, demonstrating that
small-call overhead can dominate the arithmetic ratio.

Provider and serving claims require backend-specific evidence. The next useful
matrix is PyTorch CPU, C++/LibTorch CPU, CUDA eager, compiled CUDA, backward,
and an explicitly fused placement, each across batch/token shapes and compared
with the exact surrounding projections. Every run should retain source and
binary identities, device and software versions, synchronization, warmups, raw
samples, p50/p95, memory allocation, correctness controls, and denial-path
counts.
