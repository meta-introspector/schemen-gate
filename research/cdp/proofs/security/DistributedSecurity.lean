/-
Copyright (c) 2026 Ryan R. All rights reserved.
Released under Apache 2.0; see LICENSES/Apache-2.0.txt.
Authors: Ryan R
-/
import ModelSecurityV3

/-!
# Historical Camouflage and Conditional Wrapper Models

The algebraic results about masked output preservation, permutations, and
patching retain their stated hypotheses. Statistical camouflage declarations
remain historical assumptions and are excluded from supported claims.

The former V2 global recovery axiom has been removed. The wrapper constructors
in this file now require FullEnumerationAssumption explicitly; it has no
established instance and is not a standard PRF assumption. A candidate-space
count does not bound attack cost, and a successful guess need not exhaust it.

The four remaining project-specific axioms in the imported graph are two
opaque predicates (Recovers and IsDistributionMatched) and two historical
statistical consequences (camouflage_indistinguishable and
gradient_probing_hard). None is permitted in the audited supported theorems.
Output validity proves neither confidence nor wrongness nor concealment.
-/

set_option autoImplicit false

noncomputable section

namespace Schemen.CamouflageSecurity

open Schemen Schemen.Security Schemen.SecurityV2 Schemen.SecurityV3


-- ════════════════════════════════════════════════════════════════
-- §1. CAMOUFLAGED MODEL — DEFINITIONS
-- ════════════════════════════════════════════════════════════════

/-- A camouflaged model: the original weights at authorized
    dimensions, noise at all other dimensions.

    `real_dims` is the set of dimensions belonging to the
    authorized regime. `noise_dims` is the complement.
    `camouflaged` agrees with `original` on `real_dims`. The noise field
    requires one nonzero inactive value, not a difference from `original`. -/
structure CamouflagedWeights (n : ℕ) where
  /-- The authorized regime's dimension set -/
  real_dims : Finset (Fin n)
  /-- Original weights at each hidden dimension (W2 row) -/
  original : Fin n → ℝ
  /-- Camouflaged weights (real at real_dims, noise elsewhere) -/
  camouflaged : Fin n → ℝ
  /-- Agreement on real dimensions -/
  agrees_on_real : ∀ j : Fin n, j ∈ real_dims → camouflaged j = original j
  /-- Noise dimensions have some nonzero value (nontrivial camouflage) -/
  noise_nontrivial : ∃ j : Fin n, j ∉ real_dims ∧ camouflaged j ≠ 0


-- ════════════════════════════════════════════════════════════════
-- §2. CAMOUFLAGE PRESERVES CORRECT OUTPUT
--
-- The correct mask zeros out all noise dimensions. Therefore
-- the gated activation on the camouflaged model equals the
-- gated activation on the original model.
-- ════════════════════════════════════════════════════════════════

/-- **Theorem (Camouflage Preserves Gated Activation).**
    When the correct mask (indicator of real_dims) is applied,
    the gated activation at every dimension j is identical
    between the camouflaged and original models.

    At real dimensions: mask = 1, camouflaged = original, so
    camouflaged * 1 = original * 1.

    At noise dimensions: mask = 0, so both are zeroed regardless
    of the weight values.

    This is equality of selected real coordinates, not an end-to-end
    user-experience or serving guarantee. -/
theorem camouflage_preserves_gated {n : ℕ}
    (C : CamouflagedWeights n) (j : Fin n) :
    C.camouflaged j * indicator C.real_dims j =
    C.original j * indicator C.real_dims j := by
  by_cases hj : j ∈ C.real_dims
  · rw [C.agrees_on_real j hj]
  · rw [indicator_not_mem _ j hj, mul_zero, mul_zero]

/-- The gated activation vectors are equal as functions. -/
theorem camouflage_preserves_gated_vec {n : ℕ}
    (C : CamouflagedWeights n) :
    (fun j => C.camouflaged j * indicator C.real_dims j) =
    (fun j => C.original j * indicator C.real_dims j) := by
  ext j; exact camouflage_preserves_gated C j

/-- **Theorem (Camouflage Preserves Output Logits).**
    When a model's W₂ rows are camouflaged (real weights at
    authorized dimensions, noise elsewhere), the output logits
    with the correct mask (indicator of real_dims) are identical
    to the original model's logits.

    The mask zeros out all noise W₂ rows, and the camouflaged
    weights agree with originals at real dimensions. So the
    weighted sum ∑ (h[j] · mask[j]) · W₂_camo[j,k] equals
    ∑ (h[j] · mask[j]) · W₂_orig[j,k] for every output k.

    This composes `camouflage_preserves_gated` through the linear
    output layer — it's the full correctness theorem from
    camouflaged weights to output logits. -/
theorem camouflage_preserves_logits {n o : ℕ}
    (C : CamouflagedWeights n)
    (h_act : Vec n)
    (W2_camo W2_orig : Fin n → Fin o → ℝ)
    (h_w2 : ∀ j : Fin n, j ∈ C.real_dims → ∀ k : Fin o, W2_camo j k = W2_orig j k)
    (b2 : Fin o → ℝ) :
    ∀ k : Fin o,
      output_logits (h_act ⊙ indicator C.real_dims) W2_camo b2 k =
      output_logits (h_act ⊙ indicator C.real_dims) W2_orig b2 k := by
  intro k
  simp only [output_logits, hmul]
  congr 1
  apply Finset.sum_congr rfl
  intro j _
  by_cases hj : j ∈ C.real_dims
  · rw [indicator_mem _ j hj, mul_one, h_w2 j hj k]
  · rw [indicator_not_mem _ j hj, mul_zero, zero_mul, zero_mul]


-- ════════════════════════════════════════════════════════════════
-- §3. ALL-1s ON CAMOUFLAGED MODEL DIVERGES
--
-- The all-1s mask activates every dimension. On the camouflaged
-- model, the noise dimensions contribute additional terms to the
-- logits that are not present in the original model's output.
-- ════════════════════════════════════════════════════════════════

/-- The all-1s mask: every component is 1. -/
def all_ones_mask (n : ℕ) : Vec n := fun _ => (1 : ℝ)

/-- **Lemma.** The all-1s mask is the identity for Hadamard product. -/
theorem all_ones_hadamard {n : ℕ} (v : Vec n) (j : Fin n) :
    (v ⊙ all_ones_mask n) j = v j := by
  simp [hmul, all_ones_mask, mul_one]

/-- **Theorem (All-1s Logit Decomposition).**
    With the all-1s mask, the logit at output k decomposes as:
    - The sum over REAL dimensions (same as correct-mask output)
    - PLUS the sum over NOISE dimensions (the corruption term)

    This is algebra for a sum split into two disjoint sets. The next
    theorem separately requires that the complete inactive contribution
    be nonzero; nonzero individual terms may cancel. -/
theorem all_ones_logit_decomposition {n o : ℕ}
    (h_act : Vec n) (real_dims : Finset (Fin n))
    (W2 : Fin n → Fin o → ℝ) (b2 : Fin o → ℝ) (k : Fin o) :
    output_logits (h_act ⊙ all_ones_mask n) W2 b2 k =
    output_logits (h_act ⊙ indicator real_dims) W2 b2 k +
    (Finset.univ.filter (fun x => x ∉ real_dims)).sum
      (fun j => h_act j * W2 j k) := by
  simp only [output_logits, hmul, all_ones_mask, mul_one]
  suffices h : ∑ j : Fin n, h_act j * W2 j k =
      (∑ j : Fin n, h_act j * indicator real_dims j * W2 j k) +
      (Finset.univ.filter (fun x => x ∉ real_dims)).sum
        (fun j => h_act j * W2 j k) by linarith
  have filter_eq : Finset.univ.filter (fun x => x ∈ real_dims) = real_dims := by
    ext j; simp
  trans ((Finset.univ.filter (fun x => x ∈ real_dims)).sum
      (fun j => h_act j * W2 j k) +
    (Finset.univ.filter (fun x => ¬ (x ∈ real_dims))).sum
      (fun j => h_act j * W2 j k))
  · exact (Finset.sum_filter_add_sum_filter_not Finset.univ
      (fun x => x ∈ real_dims) (fun j => h_act j * W2 j k)).symm
  · congr 1
    · rw [filter_eq, ← sum_mul_indicator_eq real_dims (fun j => h_act j * W2 j k)]
      apply Finset.sum_congr rfl
      intro j _; ring

/-- If the complete sum over inactive dimensions is nonzero at output k,
    the all-ones and selected logits differ at k. An individual nonzero
    inactive term does not suffice, because other terms may cancel. -/
theorem noise_corrupts_logits {n o : ℕ}
    (h_act : Vec n) (real_dims : Finset (Fin n))
    (W2 : Fin n → Fin o → ℝ) (b2 : Fin o → ℝ)
    (k : Fin o)
    (h_nonzero : (Finset.univ.filter (fun x => x ∉ real_dims)).sum
        (fun j => h_act j * W2 j k) ≠ 0) :
    output_logits (h_act ⊙ all_ones_mask n) W2 b2 k ≠
    output_logits (h_act ⊙ indicator real_dims) W2 b2 k := by
  intro h_eq
  have hd := all_ones_logit_decomposition h_act real_dims W2 b2 k
  exact h_nonzero (by linarith)


-- ════════════════════════════════════════════════════════════════
-- §4. PERMUTATION IS A FORWARD-PASS ISOMORPHISM
--
-- Permuting the hidden dimensions and the mask together
-- preserves the forward-pass computation. This means the
-- camouflaged model with the permuted mask produces the
-- same output as the original model with the original mask.
-- ════════════════════════════════════════════════════════════════

/-- A permutation of Fin n, represented as a bijection. -/
structure DimPermutation (n : ℕ) where
  forward : Fin n → Fin n
  inverse : Fin n → Fin n
  left_inv : ∀ j, inverse (forward j) = j
  right_inv : ∀ j, forward (inverse j) = j

/-- Permute a vector by a dimension permutation. -/
def permute_vec {n : ℕ} (σ : DimPermutation n) (v : Vec n) : Vec n :=
  fun j => v (σ.inverse j)

/-- **Theorem (Permutation Preserves Hadamard Product).**
    Permuting both operands of a Hadamard product is the same
    as permuting the result. -/
theorem permute_hadamard {n : ℕ} (σ : DimPermutation n)
    (a b : Vec n) (j : Fin n) :
    (permute_vec σ a ⊙ permute_vec σ b) j =
    permute_vec σ (a ⊙ b) j := by
  simp [hmul, permute_vec]

/-- **Theorem (Permutation Preserves Output Logits).**
    If we permute the hidden activations, the mask, and the W2
    rows consistently, the output logits are unchanged.

    This is the algebraic basis for why per-partner permutation
    does not affect the correctness of the forward pass: the
    partner's camouflaged model has permuted W2 rows and a
    permuted mask, and the computation produces the same result. -/
theorem permutation_preserves_logits {n o : ℕ}
    (σ : DimPermutation n)
    (h_act : Vec n) (mask : Vec n)
    (W2 : Fin n → Fin o → ℝ) (b2 : Fin o → ℝ) :
    ∀ k : Fin o,
      output_logits (permute_vec σ h_act ⊙ permute_vec σ mask)
        (fun j => W2 (σ.inverse j)) b2 k =
      output_logits (h_act ⊙ mask) W2 b2 k := by
  intro k
  simp only [output_logits, hmul, permute_vec]
  congr 1
  rw [show (∑ j : Fin n, h_act (σ.inverse j) * mask (σ.inverse j) *
        W2 (σ.inverse j) k) =
    ∑ j : Fin n, h_act j * mask j * W2 j k from ?_]
  exact Fintype.sum_bijective σ.inverse
    (Function.bijective_iff_has_inverse.mpr ⟨σ.forward, σ.right_inv, σ.left_inv⟩)
    _ (fun j => h_act j * mask j * W2 j k) (fun j => rfl)


-- ════════════════════════════════════════════════════════════════
-- §5. GRANT PATCHING CORRECTNESS
--
-- A fully camouflaged model (all noise) patched with the real
-- weights at the authorized dimensions produces the same output
-- as the original model with that regime's mask.
-- ════════════════════════════════════════════════════════════════

/-- **Theorem (Grant Patching Produces Correct Output).**
    Start with a fully camouflaged model (all dimensions noise).
    Patch the authorized regime's dimensions with real weights.
    Apply the authorized regime's mask.
    The output equals the original model with that regime's mask.

    Proof: the mask zeros out all unpatched (noise) dimensions.
    The patched dimensions have real weights (by construction).
    So the gated activation equals the original's gated activation
    at every dimension. -/
theorem grant_patching_correct {n : ℕ}
    (original patched : Vec n)
    (real_dims : Finset (Fin n))
    (h_patched : ∀ j : Fin n, j ∈ real_dims → patched j = original j)
    (j : Fin n) :
    patched j * indicator real_dims j =
    original j * indicator real_dims j := by
  by_cases hj : j ∈ real_dims
  · rw [h_patched j hj]
  · rw [indicator_not_mem _ j hj, mul_zero, mul_zero]


-- ════════════════════════════════════════════════════════════════
-- §6. COLLUSION RESISTANCE
--
-- Two partners with different permutations cannot align their
-- models to identify which dimensions belong to which regime.
-- The alignment problem reduces to recovering an unknown
-- permutation, which is a factorial-sized search.
-- ════════════════════════════════════════════════════════════════

/-- The composition of two permutations. -/
def compose_perm {n : ℕ} (σ τ : DimPermutation n) : DimPermutation n where
  forward := σ.forward ∘ τ.forward
  inverse := τ.inverse ∘ σ.inverse
  left_inv j := by simp [Function.comp, τ.left_inv, σ.left_inv]
  right_inv j := by simp [Function.comp, σ.right_inv, τ.right_inv]

/-- The inverse of a permutation. -/
def invert_perm {n : ℕ} (σ : DimPermutation n) : DimPermutation n where
  forward := σ.inverse
  inverse := σ.forward
  left_inv := σ.right_inv
  right_inv := σ.left_inv

/-- The relative permutation τ⁻¹ ∘ σ that an adversary must
    recover to align two partners' models. -/
def relative_perm {n : ℕ} (σ τ : DimPermutation n) : DimPermutation n :=
  compose_perm (invert_perm τ) σ

/-- **Theorem (Collusion Reduces to Permutation Recovery).**
    To align partner σ's model with partner τ's model, the
    adversary must apply the relative permutation τ⁻¹ ∘ σ.
    Without knowing this permutation, the adversary sees
    the same logical dimension at different physical indices
    in the two models.

    The search space for the relative permutation is n!.
    For n = 768, n! ≈ 10^1870, vastly exceeding the partition
    search space C(768,384) ≈ 10^230. -/
theorem collusion_reduces_to_perm_recovery {n : ℕ}
    (σ τ : DimPermutation n) (v : Vec n) (j : Fin n) :
    permute_vec σ v j =
    permute_vec τ v (τ.forward (σ.inverse j)) := by
  simp [permute_vec, τ.left_inv]

/-- **Theorem (Different Permutations Scramble Indices).**
    If two permutations disagree at some index (which they will
    with overwhelming probability for random permutations), then
    the same physical index in the two models maps to different
    logical dimensions. Direct index-by-index comparison of the
    two models is therefore uninformative. -/
theorem different_perms_scramble {n : ℕ}
    (σ τ : DimPermutation n) (j : Fin n)
    (h_diff : σ.inverse j ≠ τ.inverse j) (v : Vec n)
    (h_inj : Function.Injective v) :
    permute_vec σ v j ≠ permute_vec τ v j := by
  simp only [permute_vec]
  exact fun h => h_diff (h_inj h)


-- ════════════════════════════════════════════════════════════════
-- §7. WEIGHT STATISTICAL INDISTINGUISHABILITY (AXIOM)
--
-- The load-bearing assumption for distributed model security.
-- ════════════════════════════════════════════════════════════════

/-- A noise generation scheme applied to a camouflaged model.
    Captures the structural relationship between real and noise
    weight vectors: for every dimension, the weight is either
    the real trained weight (at authorized dims) or a noise vector
    (at non-authorized dims).

    The `real_dims` partition is the adversary's unknown. -/
structure NoiseScheme (n : ℕ) where
  real_dims : Finset (Fin n)
  weights : Fin n → ℝ
  real_source : Fin n → ℝ
  noise_source : Fin n → ℝ
  at_real : ∀ j, j ∈ real_dims → weights j = real_source j
  at_noise : ∀ j, j ∉ real_dims → weights j = noise_source j

/-- An adversary attempting to distinguish real from noise weights.
    The distinguisher takes a weight vector and returns a set of
    indices it classifies as "real." The adversary succeeds if this
    set equals `real_dims`. -/
structure WeightDistinguisher (n : ℕ) where
  classify : (Fin n → ℝ) → Finset (Fin n)

/-- The distinguisher succeeds: it correctly identifies the real
    dimensions from the camouflaged weight vector. -/
def DistinguisherSucceeds {n : ℕ}
    (N : NoiseScheme n) (D : WeightDistinguisher n) : Prop :=
  D.classify N.weights = N.real_dims

/-- Historical opaque predicate with no statistical model or supplied instance.
    Empirical moment matching does not establish this Lean proposition or
    the universal distinguisher exclusions below. It is outside supported
    claims and is retained only to keep the historical chain inspectable. -/
axiom IsDistributionMatched {n : ℕ} : NoiseScheme n → Prop

/-- Historical, unvalidated universal distinguisher exclusion conditioned on
    the opaque IsDistributionMatched predicate. This is not a standard
    cryptographic assumption or an empirical distribution-matching result.
    It has no supported security interpretation. -/
axiom camouflage_indistinguishable {n : ℕ}
    (N : NoiseScheme n) (D : WeightDistinguisher n)
    (hN : IsDistributionMatched N) :
    ¬ DistinguisherSucceeds N D


-- ════════════════════════════════════════════════════════════════
-- §8. GRADIENT PROBING HARDNESS
-- ════════════════════════════════════════════════════════════════

/-- A gradient-based distinguisher: the adversary computes
    gradients through the model with chosen inputs and attempts
    to classify each dimension as real or noise. -/
structure GradientDistinguisher (n : ℕ) where
  classify : (Fin n → ℝ) → Finset (Fin n)

/-- Historical, unvalidated exclusion conditioned only on the opaque
    IsDistributionMatched predicate. There is no training-data restriction,
    observation model, or probabilistic success bound in this statement.
    It is excluded from supported security claims. -/
axiom gradient_probing_hard {n : ℕ}
    (N : NoiseScheme n) (G : GradientDistinguisher n)
    (hN : IsDistributionMatched N) :
    ¬ (G.classify N.weights = N.real_dims)


-- ════════════════════════════════════════════════════════════════
-- §9. DISTRIBUTED SAFETY V4 — COMPREHENSIVE MAIN THEOREM
-- ════════════════════════════════════════════════════════════════

/-- Historical package of arithmetic, local algebra, and unvalidated
    premises. The field names do not establish distributable artifact safety. -/
structure DistributableSafetyV4 (n R : ℕ) where
  /-- Nominal support-count inequality, not a security level. -/
  combinatorial_hardness :
    2 ^ 256 ≤ Nat.choose n (n / R)

  /-- No standard cryptographic assumption establishes this field. -/
  no_shortcut :
    ∀ (S : CryptoScheme n R) (A : RecoveryAttempt n R)
      (_T : ThreatModel n R),
      Recovers A S → Nat.choose n (n / R) ≤ A.queries

  /-- V1: Wrong mask reads wrong dimensions -/
  steganographic_mask :
    ∀ (P : ValidPartition n R) (r s : Fin R),
      r ≠ s → ∀ j : Fin n, j ∈ P.groups r →
      indicator (P.groups s) j = 0

  /-- Validity of real softmax for any mask; no behavioral conclusion. -/
  steganographic_output :
    ∀ (o : ℕ) (_ho : 0 < o)
      (h_act : Vec n) (W2 : Fin n → Fin o → ℝ) (b2 : Fin o → ℝ)
      (mask : Vec n),
      let logits := output_logits (h_act ⊙ mask) W2 b2
      (∀ k : Fin o, 0 < softmax logits k)
      ∧ (∑ k : Fin o, softmax logits k = 1)

  /-- V4 NEW: Correct mask on camouflaged model preserves output -/
  camouflage_preserves :
    ∀ (C : CamouflagedWeights n) (j : Fin n),
      C.camouflaged j * indicator C.real_dims j =
      C.original j * indicator C.real_dims j

  /-- V4 NEW: Grant patching produces correct gated activation -/
  grant_patching :
    ∀ (original patched : Vec n) (real_dims : Finset (Fin n)),
      (∀ j : Fin n, j ∈ real_dims → patched j = original j) →
      ∀ j : Fin n,
        patched j * indicator real_dims j =
        original j * indicator real_dims j

  /-- V4 NEW: No distinguisher can identify real vs noise dims
      (conditioned on distribution-matched noise) -/
  camouflage_indist :
    ∀ (N : NoiseScheme n) (D : WeightDistinguisher n),
      IsDistributionMatched N →
      ¬ DistinguisherSucceeds N D

/-- Historical conditional wrapper. Requires a caller-supplied recovery
    premise and retains the excluded statistical camouflage assumption. -/
theorem standard_is_distributable_safe_v4
    (h_enumeration : FullEnumerationAssumption 768 2) :
    DistributableSafetyV4 768 2 where
  combinatorial_hardness := standard_support_count_ge_two_pow_256
  no_shortcut := h_enumeration
  steganographic_mask := fun P r s hrs j hj =>
    wrong_mask_reads_wrong_dims P r s hrs j hj
  steganographic_output := fun o ho h_act W2 b2 mask =>
    ⟨fun k => softmax_pos ho _ k, softmax_sum_one ho _⟩
  camouflage_preserves := fun C j =>
    camouflage_preserves_gated C j
  grant_patching := fun original patched real_dims h_patched j =>
    grant_patching_correct original patched real_dims h_patched j
  camouflage_indist := fun N D hN =>
    camouflage_indistinguishable N D hN


-- ════════════════════════════════════════════════════════════════
-- §10. END-TO-END SECURITY CHAIN V4
-- ════════════════════════════════════════════════════════════════

/-- Historical alias for the same explicitly conditional wrapper.
    This is not a supported end-to-end confidentiality claim. -/
theorem end_to_end_chain_v4
    (h_enumeration : FullEnumerationAssumption 768 2) :
    DistributableSafetyV4 768 2 :=
  standard_is_distributable_safe_v4 h_enumeration


end Schemen.CamouflageSecurity
