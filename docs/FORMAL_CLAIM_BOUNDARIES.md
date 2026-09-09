# Formal claim boundaries

The supported claim map distinguishes local algebra, implementation tests, and
external cryptographic assumptions. The following corrections preserve the
runtime authorization, key derivation, and numerical Gate behavior.

## Recovery and cardinality

The former global `prf_brute_force_optimal` axiom has been removed. Its
historical name is now a theorem requiring an explicit
`FullEnumerationAssumption`; no instance of that premise is supplied. The
historical V2/V3/V4 wrapper constructors also require it. This is a deliberate
change to the research theorem interface, not a new security guarantee.

The binomial results count nominal supports. A successful guess need not
exhaust that space: among six equally likely supports, one fixed guess succeeds
with probability 1/6. The opaque `Recovers` declaration does not model sampled
keys, trained-weight observations, a strategy, or a success probability.
Deterministically deriving masks from a 32-byte key adds no key entropy. Neither
the candidate count nor the explicit premise establishes an AES-comparable
recovery-work bound.

Use `standard_support_count_ge_two_pow_256` and
`cross_regime_updates_and_mask_zero` for the actual arithmetic and local
exclusion statements. Historical names referring to AES strength or extraction
remain compatibility aliases with the narrower interpretation documented.

## Output validity and independence

`gated_output_valid_distribution` proves that real-valued masked logits produce
positive softmax probabilities summing to one when the output dimension is
nonempty. The compatibility name `wrong_key_valid_distribution` carries only
that statement. Neither establishes correctness, confidence, calibration, or
statistical concealment. Real arithmetic does not prove floating-point softmax
behavior for nonfinite active logits.

The security-relevant invariance results are separately scoped:

- `regime_output_independent_of_others`: fixing active hidden values, projection,
  and bias makes logits independent of inactive hidden coordinates. An upstream
  computation that changes active values is outside that premise.
- `autoregressive_independent_of_inactive`: adapter families agreeing on the
  active set give equal modeled generation, with the frozen functions, prompt,
  and deterministic sampler fixed. This is not a serving or GPU refinement proof.

Distinct regimes in one valid partition are disjoint. Masks derived from
different keys need not be. A raw mask is not an authorization decision;
governed requests must still be denied before protected access when authority
is invalid. No rejected request is routed into another tenant's lane.

## Executable evidence

The [transitive axiom audit](../research/cdp/scripts/lean_claim_audit.lean)
includes the cardinality, output-validity, and independence results. Its
enforcement script rejects project-specific or unsafe axioms in the selected
theorems. Historical wrappers are excluded from that supported set.

The [finite controls](../research/cdp/experiments/tests/test_output_claim_boundaries.py)
retain a uniform valid distribution, a bias-only answer correct under both
regimes, and the six-support guessing example. The tensor independence control
includes an effective active-coordinate mutation as a positive control. These
tests falsify overbroad interpretations; they are not production cryptanalysis.

Wrong-regime task accuracy or concealment can be studied under explicit task,
data, observation, and evaluation protocols. Such empirical findings must not
be inferred from the softmax lemma alone.
