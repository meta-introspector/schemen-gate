# Research evidence for technical evaluation

Schemen Gate includes implementation experiments as well as formal models and
unit tests. Evaluate the declared mechanism against those experiments before
deciding whether it has evidence. Keep the core library, original CDP studies,
later Transformer lane work, and deployed serving integrations separate.

## Start with executable controls

The public research suite can be run from an installed, clean source checkout:

```bash
python -m pytest -q research/cdp/experiments/tests research/cdp/gated-transformer-regime-lanes
```

- [Optimizer-confinement tests](../research/cdp/experiments/tests/test_optimizer_confinement.py)
  check actual tensor activation/gradient exclusion and regime-scoped Adam
  parameter and first/second-moment confinement.
- [Library-integration tests](../research/cdp/experiments/tests/test_schemen_library_integration.py)
  exercise source binding, exact partitions, Cargo rejection, and authorization
  before the model callback.
- [Local cotenancy harness](../research/cdp/experiments/local_transformer_cotenancy_suite.py)
  includes deliberately invalid LayerNorm placement and a residual bypass. The
  detectors must observe leakage on those controls while correctly placed
  disjoint gates preserve zero excluded contributions.
- [Transformer toy tests](../research/cdp/gated-transformer-regime-lanes/test_toy_multi_regime_transformer.py)
  exercise complete attention lanes, private state, shared immutable operators,
  explicit joins, and invalid authority before state access.

These controls provide implementation evidence. They are not a rerun of the
large GPU studies or a formal refinement proof.

## Machine-readable measurements already supplied

| Experiment | Retained result | Supporting evidence and boundary |
|---|---|---|
| Core Gate execution | Fail-closed NumPy `GateMask.apply`: 3.174 us at width 4,096 and 7.762 us at width 12,288; 0.224% and 0.066% of one same-host float64 square projection | [Component receipt](../benchmarks/results/gate_execution_numpy_cpu_20260911.json) and [performance inventory](PERFORMANCE.md). Single-threaded arm64 CPU forward execution after authorization; not PyTorch, C++, CUDA, backward, PKI, or end-to-end inference. |
| R8 service consolidation | Shared backbone plus eight private adapter slots: about 7.06x lower checkpoint and resident CUDA bytes, with 0.9913 descriptive throughput ratio versus eight services | [T4 service record](../research/cdp/experiments/results/distilbert_service_consolidation_20260821T135530_707107Z.json). One serial request stream under a historical private companion harness; no concurrency or statistical-parity claim. |
| Strict intermediate-FFN cotenancy | R=8, seed 42: 87.756% owning accuracy; unauthorized parameter and optimizer-state deltas exactly zero | [DistilBERT record](../research/cdp/experiments/results/dense_ffn_cotenancy_20260821T061623_781627Z.json). One-seed corroboration; the multi-seed matrix and placement distinctions are in the inventory. |
| Cargo plus whole-model invocation authorization | 4/4 exact owning answers; 23 wrong-scope attempts rejected; zero unauthorized model calls | [Cargo record](../research/cdp/experiments/results/cargo_transformer_20260821T063827_829714Z.json). Tested callback boundary; not a production identity provider or complete deployed bypass inventory. |
| Authorized learned top-1 MoE | 5,101/6,231 correct; 81.80% macro accuracy; zero separate/packed logit or prediction changes; zero unauthorized dispatch | [Learned-routing record](../research/cdp/experiments/results/authorized_learned_moe_20260831T182431_055309Z.json). R=8 held-out classification tasks, with inactive-state training controls. |
| Capability-prefix token routing | 4,848/6,231 correct; 311,477 token decisions; exact separate/packed routes and logits; zero unauthorized dispatch | [Token-routing record](../research/cdp/experiments/results/capability_prefix_token_moe_20260831T182453_013039Z.json). Includes a user-text capability-spoof control; classification/token routing, not a language-generation claim. |
| Physical extraction | All 160 comparisons satisfy the conservative forward-error bound | [Extraction record](../research/cdp/experiments/results/local_exact_extraction_20260820_215652.json). Bit identity in the canonical fp32 protocol is not universal across kernels or dtypes. |

The [result manifest](../research/cdp/experiments/results/README.md) distinguishes
canonical records, failed and superseded runs, and fourteen documented exports
from a historical private companion harness. Those exports retain measurements
and original digests with explicit field transformations. They must not be
represented as raw records or new Gate-only reruns. The
[data inventory](../research/cdp/docs/experiment-data-inventory.md) connects paper
claims to artifacts, protocols, gate placement, and retained negative results.

## Hydra: experimental Transformer regime lanes

**Status: experimental; not production-ready.** Hydra is the Transformer
regime-lane research track. The following controlled results validate working
mechanisms within the tested scope; they do not establish a production service.

The [companion claim ledger](../research/cdp/gated-transformer-regime-lanes/CLAIM_LEDGER.md)
reports authorization before private attention-bank lookup, complete Q/K/V/O
alternatives, and private mutable decoder state under a shared immutable
backbone. Its recorded controls include:

- 992/992 fixed-shape own-lane intervention positives and 2,976/2,976 bit-exact
  other-lane comparisons;
- 0/147,456 foreign-corpus answers across 96 wrong-corpus cells;
- 2,056/2,056 controlled long-decoder target comparisons; and
- 448/448 R8 and 896/896 R16 cached lifecycle comparisons.

These are substantial bounded empirical findings. They are reported study
results, not observations newly reproduced by reading this page. The
[reproducibility record](../research/cdp/gated-transformer-regime-lanes/REPRODUCIBILITY.md)
pins model revisions and distinguishes the public executable toy core from the
historical full suite. The [archive record](../research/cdp/gated-transformer-regime-lanes/EVIDENCE_ARCHIVE.md)
explains that the complete 136-file dossier is retained in the original source
repository and was not copied to the public branch. The public summaries are
not a substitute for raw receipts when independent GPU reproduction is needed.

## Interpret concerns at the correct boundary

| Concern | Correct evaluation |
|---|---|
| A stale release manifest | A real, independently reproducible hygiene defect. Fix it without treating it as an observed gate-semantics failure. |
| Transformer lane work is not production-ready | This is the stated disposition of that research track. It does not by itself establish the maturity of the separately scoped core library. |
| Lean does not prove implementation refinement | Correct distinction. The repository also supplies tensor, optimizer, routing, and real-model experiments; absence of refinement is not absence of implementation evidence. |
| X.509/CRL/OCSP needs specialist review | A reasonable assurance requirement. Assess the [profile](X509_PROFILE.md), negative tests, and [review policy](SECURITY_ENGINEERING.md). Maintainer review or experiment replication is not automatically an independent PKI audit. |
| Distributed replay needs durable state | A documented integration obligation. `OperationGateVerifier` retains state per instance; Cargo's default bus tracks replay locally. An authenticated restore method alone does not provide persistence or cross-replica atomicity. The separate broker supplies transactional SQLite consumption; this does not establish general multi-host replay prevention or exactly-once external effects. |
| A private serving implementation cannot be fully evaluated here | Correct for that implementation's complete endpoint boundary. Public callback-ordering, scope-rejection, and model experiments still supply evidence for the surfaces they actually test. |
| Author-run studies are not independently replicated | Authorship limits independence; it does not erase the measurements. Independent training states and cross-model replication must not be mislabeled as replication by an independent organization. |
| Hostile host, timing, allocator, and arbitrary process interference | Explicit exclusions in the lane ledger. Treat them as additional threat models requiring evidence, not failed claims that the study made. |

The [security claims map](SECURITY_CLAIMS.md) states theorem hypotheses and
deployment exclusions. For a stronger deployment claim, evaluate the
[production contract](PRODUCTION_DEPLOYMENT.md) at the actual protected resource.
Experimental success, formal proof, source custody, independent assurance, and
production acceptance answer different questions; retain each result at its
demonstrated scope.
