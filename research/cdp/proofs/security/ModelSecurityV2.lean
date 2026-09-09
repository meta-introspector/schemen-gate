/-
Copyright (c) 2026 Ryan R. All rights reserved.
Released under Apache 2.0; see LICENSES/Apache-2.0.txt.
Authors: Ryan R
-/


import Mathlib.Analysis.SpecialFunctions.Log.Basic
import ModelSecurity

/-!
# Output Validity and Historical Recovery Assumptions — V2

The softmax results establish a valid distribution over exact real logits.
They establish no answer correctness, confidence, calibration, or statistical
indistinguishability. The runtime floating-point behavior is a separate contract.

The former global `prf_brute_force_optimal` axiom has been removed. Its bound
is retained as an explicit `FullEnumerationAssumption` supplied by callers of
historical wrapper theorems. It is not a consequence of ordinary PRF security
and no instance is established here. A recovery game would need key sampling,
adversary observations (including trained weights), costs, and success
probability. An opaque success predicate does not supply that game.
-/

set_option autoImplicit false

noncomputable section

namespace Schemen.SecurityV2

open Schemen Schemen.Security


-- ════════════════════════════════════════════════════════════════
-- §1. STRENGTHENED ADVERSARY MODEL  (fixes H1, H2, H7)
-- ════════════════════════════════════════════════════════════════

/-- A positive candidate budget, not a computational adversary model. -/
structure RecoveryAttempt (n R : ℕ) where
  /-- Number of candidate partitions the adversary evaluates -/
  queries : ℕ
  /-- The adversary claims this suffices for recovery -/
  queries_pos : 0 < queries

/-- Threat-model marker type.

    Originally defined as a structure with four `True`-typed fields
    documenting operational assumptions (weight access under Kerckhoffs'
    principle, architecture knowledge, lack of regime-specific training
    data, lack of the master key). The fake fields were removed in the
    April 2026 adversarial review because they inflated the axiom/field
    count without constraining anything.

    The structure is retained as an empty marker only so that existing
    call sites of `prf_brute_force_optimal` compile without rewriting
    every downstream file. The operational assumptions the old fields
    described are documented in `docs/executive-summary.md` and
    `docs/compliance-mapping.md` — they are deployment requirements,
    not formal constraints. -/
structure ThreatModel (n R : ℕ) : Type where
  -- empty: all fields were vacuous and were removed.

/-- Historical opaque recovery predicate. It has no executable strategy,
    sampled key, observation transcript, or success probability. Inability
    to prove this predicate is not evidence that a real attack fails. -/
axiom Recovers {n R : ℕ} : RecoveryAttempt n R → CryptoScheme n R → Prop

/-- Unvalidated historical recovery premise, not a standard PRF assumption.
    A successful guess need not enumerate the space. This proposition has
    no supplied instance and is excluded from supported security claims. -/
def FullEnumerationAssumption (n R : ℕ) : Prop :=
  ∀ (S : CryptoScheme n R) (A : RecoveryAttempt n R) (_T : ThreatModel n R),
    Recovers A S → Nat.choose n (n / R) ≤ A.queries

/-- Historical compatibility name. The recovery bound now requires an
    explicit unvalidated premise; it is no longer a global axiom. -/
theorem prf_brute_force_optimal {n R : ℕ}
    (h_enumeration : FullEnumerationAssumption n R)
    (S : CryptoScheme n R) (A : RecoveryAttempt n R)
    (T : ThreatModel n R)
    (_hn : 0 < n) (_hR : 0 < R) (_hdiv : R ∣ n)
    (h_success : Recovers A S) :
    Nat.choose n (n / R) ≤ A.queries :=
  h_enumeration S A T h_success


-- ════════════════════════════════════════════════════════════════
-- §2. SOFTMAX — CONCRETE DEFINITION AND PROPERTIES  (fixes H5)
--
-- This section proves output validity for exact real logits. It makes no
-- behavioral or authorization claim and does not model IEEE arithmetic.
-- ════════════════════════════════════════════════════════════════

/-- Softmax denominator: Z(v) = Σ exp(v_k). Always positive because
    exp is always positive. -/
def softmax_denom {n : ℕ} (v : Fin n → ℝ) : ℝ :=
  ∑ k : Fin n, Real.exp (v k)

/-- The softmax function: maps arbitrary logits to a probability
    distribution. This is the standard definition used in neural
    network output layers.

    softmax(v)_j = exp(v_j) / Σ_k exp(v_k) -/
def softmax {n : ℕ} (v : Fin n → ℝ) : Fin n → ℝ :=
  fun j => Real.exp (v j) / softmax_denom v

/-- The softmax denominator is strictly positive. -/
theorem softmax_denom_pos {n : ℕ} (hn : 0 < n) (v : Fin n → ℝ) :
    0 < softmax_denom v := by
  apply Finset.sum_pos
  · intro k _; exact Real.exp_pos _
  · exact ⟨⟨0, hn⟩, Finset.mem_univ _⟩

/-- The softmax denominator is nonzero (convenience lemma). -/
theorem softmax_denom_ne_zero {n : ℕ} (hn : 0 < n) (v : Fin n → ℝ) :
    softmax_denom v ≠ 0 :=
  ne_of_gt (softmax_denom_pos hn v)

/-- **Theorem.** Every softmax output is strictly positive.

    This is exact real arithmetic, whose domain contains no NaN. It does
    not prove that a floating-point implementation avoids underflow. -/
theorem softmax_pos {n : ℕ} (hn : 0 < n) (v : Fin n → ℝ) (j : Fin n) :
    0 < softmax v j :=
  div_pos (Real.exp_pos _) (softmax_denom_pos hn v)

/-- **Theorem.** Softmax outputs sum to exactly 1.

    Combined with positivity, this proves softmax outputs a valid
    probability distribution for ANY input logits — including
    logits computed from the wrong mask.

    Proof: Σ_j [exp(v_j) / Z] = (Σ_j exp(v_j)) / Z = Z / Z = 1. -/
theorem softmax_sum_one {n : ℕ} (hn : 0 < n) (v : Fin n → ℝ) :
    ∑ j : Fin n, softmax v j = 1 := by
  simp only [softmax]
  rw [← Finset.sum_div]
  exact div_self (softmax_denom_ne_zero hn v)

/-- **Theorem.** Each softmax output is at most 1. -/
theorem softmax_le_one {n : ℕ} (hn : 0 < n) (v : Fin n → ℝ) (j : Fin n) :
    softmax v j ≤ 1 := by
  unfold softmax
  rw [div_le_one (softmax_denom_pos hn v)]
  exact Finset.single_le_sum (fun k _ => le_of_lt (Real.exp_pos _))
    (Finset.mem_univ j)


-- ════════════════════════════════════════════════════════════════
-- §3. GATED OUTPUT VALIDITY
-- ════════════════════════════════════════════════════════════════

/-- Output logits of the gated MLP: logits_k = Σ_j gated_j · W2_{j,k} + b2_k.
    This is the linear transformation from gated hidden layer to output. -/
def output_logits {n o : ℕ} (gated : Fin n → ℝ) (W2 : Fin n → Fin o → ℝ)
    (b2 : Fin o → ℝ) : Fin o → ℝ :=
  fun k => (∑ j : Fin n, gated j * W2 j k) + b2 k

/-- For nonempty output and any real-valued mask, softmax yields positive
    probabilities summing to one. There is no authorization, correctness,
    confidence, calibration, or indistinguishability conclusion. -/
theorem gated_output_valid_distribution {n o : ℕ} (_hn : 0 < n) (ho : 0 < o)
    (h_act : Vec n) (W2 : Fin n → Fin o → ℝ) (b2 : Fin o → ℝ)
    (mask : Vec n) :
    let logits := output_logits (h_act ⊙ mask) W2 b2
    (∀ k : Fin o, 0 < softmax logits k)
    ∧ (∑ k : Fin o, softmax logits k = 1)
    ∧ (∀ k : Fin o, softmax logits k ≤ 1) :=
  ⟨fun k => softmax_pos ho _ k,
   softmax_sum_one ho _,
   fun k => softmax_le_one ho _ k⟩

/-- Compatibility alias for output validity only. A different key is not
    assumed disjoint, and output validity does not imply wrong answers. -/
theorem wrong_key_valid_distribution {n o : ℕ} (hn : 0 < n) (ho : 0 < o)
    (h_act : Vec n) (W2 : Fin n → Fin o → ℝ) (b2 : Fin o → ℝ)
    (mask : Vec n) :
    let logits := output_logits (h_act ⊙ mask) W2 b2
    (∀ k : Fin o, 0 < softmax logits k)
    ∧ (∑ k : Fin o, softmax logits k = 1)
    ∧ (∀ k : Fin o, softmax logits k ≤ 1) :=
  gated_output_valid_distribution hn ho h_act W2 b2 mask


-- ════════════════════════════════════════════════════════════════
-- §4. DISTRIBUTABLE SAFETY V2 — STRENGTHENED MAIN THEOREM
-- ════════════════════════════════════════════════════════════════

-- DistributableSafetyV2, standard_is_distributable_safe_v2,
-- cheap_attempt, cheap_attempt_cannot_succeed, and
-- end_to_end_chain_v2 have been moved to DistributableClaims.lean.
-- ════════════════════════════════════════════════════════════════


end Schemen.SecurityV2
