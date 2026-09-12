# Hydra code boundary

## Decision

Hydra is a model-serving architecture, not a second Gate implementation. The
installed Gate package owns objective authority and enforcement primitives.
The serving integration owns model topology and execution. The checked-in
Hydra experiments remain repository-only research evidence and are not
installed APIs.

This split lets an admitted multi-lane transaction run at full model speed
without weakening Gate integrity. Admission is the objective boundary; token
generation is not a new authorization event.

## Ownership

| Gate library | Serving integration | Research record |
|---|---|---|
| Verify signed identity, capability scope, expiry, artifact binding, and release identity | Construct the shared backbone and private lane state | Preserve protocols, inputs, failures, corrections, and measured results |
| Resolve the admitted Regime roster and refuse invalid authority before model access | Seal one transaction topology and batch all admitted lanes in one pass | Keep experimental code outside the installed package |
| Supply immutable masks and scoped capability material | Own per-lane KV cache, position, stopping, cancellation, and mutable state | State the exact hardware, model revision, denominator, and claim boundary |
| Reverify bound completion evidence before accepting a receipt | Own shared decoding, final-position vocabulary projection, memory allocation, scheduling, and profiling | Add new result artifacts instead of rewriting failed runs |

Gate does not own model weights, attention banks, adapters, KV caches, decoder
projection, CUDA allocation, continuous batching, request cancellation, or
throughput policy. A serving layer must not turn a caller-provided lane number
or mask into authority; it receives only the roster resolved from verified
Gate material.

## Transaction boundary

One inference transaction should follow this order:

1. Verify identity, capability, expiry, model and release bindings.
2. Resolve and seal the complete admitted roster.
3. Lock the topology for that transaction.
4. Run every admitted lane together through topology-aware batching while
   preserving lane-local mutable state.
5. Reverify completion and artifact bindings.
6. Publish per-lane outputs and receipts.

The serving layer must not repeat admission, signature verification, model
loading, or topology construction inside the token loop. It must also not
merge lane-local caches or publish output from a roster that differs from the
sealed transaction.

## Gate package cleanup

The only installed module whose name implied Hydra ownership was
`_regime0_fold.py`. Its implementation was a NumPy reshape codec and always
stamped the metadata label `source_regime_id=0`; it never applied a Gate.

The canonical implementation now lives in `_row_folding.py` and says exactly
what it does: validated, lossless row representation. The former private module
is a compatibility re-export. Stable package-root exports are unchanged for
the 1.x API. Malformed row counts, ranks, metadata shapes, and inconsistent
batches now fail with explicit errors instead of incidental NumPy or division
errors.

## Falsifiable checks

- The base package dependency set contains NumPy but no model framework or
  serving engine.
- No Hydra scheduler, lane model, attention bank, KV cache, or decoder lives
  under `src/schemen_gate`.
- `schemen_gate.fold_vector` and the legacy private import resolve to the same
  generic implementation.
- Fold/unfold remains lossless for valid vectors and real-model fixtures.
- Invalid topology fails before reshaping or reconstruction.
- Folding remains explicitly excluded from the Gate and storage-authority
  claims.

These checks establish code ownership and codec behavior. They do not certify
the experimental Hydra architecture or a deployed serving path.
