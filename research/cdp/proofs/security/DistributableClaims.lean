/-
Copyright (c) 2026 Ryan R. All rights reserved.
Released under Apache 2.0; see LICENSES/Apache-2.0.txt.
Authors: Ryan R
-/
import DistributedSecurity

-- The conditional arithmetic below compares powers up to 2^384.
set_option exponentiation.threshold 512

/-!
# Historical Conditional Wrappers — Not Supported Security Guarantees

The recovery bound is now an explicit FullEnumerationAssumption, with no
instance established here and no reduction from PRF security. Historical
structure/field names do not establish cryptographic hardness, confident
wrongness, or concealment. Statistical camouflage assumptions remain excluded
from the supported claim set. Algebraic results retain their exact hypotheses.

# Distributable Safety Claims — Consolidated

This file consolidates the "distributable safety" wrapper structures
from V1, V2, and V3 into a single location. These structures package
local algebra and unvalidated premises under historical structure names.
They do not establish a supported distributable-safety conclusion.

**Why separated**: Patent E (Distributable Inert Artifact) is deferred
from initial filing. The core gate theorems (gradient isolation, weight
confinement, mask exclusion, etc.) remain in their original files
(GateSecurity.lean, ModelSecurity.lean, ModelSecurityV2.lean,
ModelSecurityV3.lean). This file contains only the distributable-safety
*framing* — the structures that package those theorems into a
"distributable safety" conclusion.

For the Weight Camouflage proofs (V4), see DistributedSecurity.lean.

## Contents

- `DistributableSafety` (V1): removed historical wrapper
- `DistributableSafetyV2` (V2): adds output validity (valid softmax)
- `DistributableSafetyV3` (V3): adds conditional reachability, regime locality,
  a universally quantified mask identity, and pointwise gradient confinement
- Consequence of an explicitly supplied recovery premise (cheap_attempt_cannot_succeed)
- End-to-end security chains V1, V2, V3
-/

set_option autoImplicit false

noncomputable section


-- ════════════════════════════════════════════════════════════════
-- §1. (REMOVED) V1 DISTRIBUTABLE SAFETY
--
-- Previous versions contained `DistributableSafety` (V1), whose
-- `no_shortcut` field had type `∀ S, C(n,n/R) ≤ C(n,n/R)` — trivially
-- `le_refl`. Removed in the April 2026 adversarial review along with
-- the `prf_implies_no_shortcut` axiom it depended on (see
-- ModelSecurity.lean).
--
-- The V2 structure (`DistributableSafetyV2` below) supersedes it.
-- V2's `no_shortcut` quantifies over `RecoveryAttempt` and constrains
-- the query budget. Its bound must now be supplied as an explicit premise.
-- ════════════════════════════════════════════════════════════════


-- ════════════════════════════════════════════════════════════════
-- §2. V2 DISTRIBUTABLE SAFETY
-- ════════════════════════════════════════════════════════════════

namespace Schemen.SecurityV2

open Schemen Schemen.Security

/-- Historical wrapper combining local algebra with an unvalidated premise.
    `no_shortcut` is supplied explicitly, not derived from a PRF game.
    `steganographic_output` states normalization over exact real logits only.
    The threat-model marker has no fields or computational semantics. -/
structure DistributableSafetyV2 (n R : ℕ) where
  combinatorial_hardness :
    2 ^ 256 ≤ Nat.choose n (n / R)
  no_shortcut :
    ∀ (S : CryptoScheme n R) (A : RecoveryAttempt n R)
      (_T : ThreatModel n R),
      Recovers A S → Nat.choose n (n / R) ≤ A.queries
  steganographic_mask :
    ∀ (P : ValidPartition n R) (r s : Fin R),
      r ≠ s → ∀ j : Fin n, j ∈ P.groups r →
      indicator (P.groups s) j = 0
  steganographic_output :
    ∀ (o : ℕ) (_ho : 0 < o)
      (h_act : Vec n) (W2 : Fin n → Fin o → ℝ) (b2 : Fin o → ℝ)
      (mask : Vec n),
      let logits := output_logits (h_act ⊙ mask) W2 b2
      (∀ k : Fin o, 0 < softmax logits k)
      ∧ (∑ k : Fin o, softmax logits k = 1)

theorem standard_is_distributable_safe_v2
    (h_enumeration : FullEnumerationAssumption 768 2) :
    DistributableSafetyV2 768 2 where
  combinatorial_hardness := standard_support_count_ge_two_pow_256
  no_shortcut := h_enumeration
  steganographic_mask := fun P r s hrs j hj =>
    wrong_mask_reads_wrong_dims P r s hrs j hj
  steganographic_output := fun o ho h_act W2 b2 mask =>
    ⟨fun k => softmax_pos ho _ k, softmax_sum_one ho _⟩

/-- A "cheap" recovery attempt: only 2^40 queries. -/
def cheap_attempt : RecoveryAttempt 768 2 where
  queries := 2 ^ 40
  queries_pos := by omega

/-- Conditional consequence of the supplied unvalidated enumeration premise.
    This is not a proved real-world recovery bound. -/
theorem cheap_attempt_cannot_succeed
    (h_enumeration : FullEnumerationAssumption 768 2)
    (S : CryptoScheme 768 2) (T : ThreatModel 768 2)
    (h_rec : Recovers cheap_attempt S) :
    False := by
  have h1 : 2 ^ 384 ≤ cheap_attempt.queries :=
    le_trans standard_exceeds_2_384
      (h_enumeration S cheap_attempt T h_rec)
  have h2 : cheap_attempt.queries = 2 ^ 40 := rfl
  rw [h2] at h1
  exact absurd h1 (not_le.mpr (Nat.pow_lt_pow_right (by omega) (by omega)))

theorem end_to_end_chain_v2
    (h_enumeration : FullEnumerationAssumption 768 2) :
    DistributableSafetyV2 768 2 :=
  standard_is_distributable_safe_v2 h_enumeration

end Schemen.SecurityV2


-- ════════════════════════════════════════════════════════════════
-- §3. V3 DISTRIBUTABLE SAFETY
-- ════════════════════════════════════════════════════════════════

namespace Schemen.SecurityV3

open Schemen Schemen.Security Schemen.SecurityV2

/-- Historical V3 wrapper with the explicit enumeration premise.

    Adds to V2:
    • weight_indistinguishable: a reachability statement conditional on
      IsSurjective T; no posterior or information-theoretic claim
    • regime_locality: selected-coordinate sum under a fixed projection
    • exact_mask: equality for every activation and projection forces mask equality
    • compositional_confinement: pointwise zero for a masked upstream scalar -/
structure DistributableSafetyV3 (n R : ℕ) where
  combinatorial_hardness :
    2 ^ 256 ≤ Nat.choose n (n / R)
  no_shortcut :
    ∀ (S : CryptoScheme n R) (A : RecoveryAttempt n R)
      (_T : ThreatModel n R),
      Recovers A S → Nat.choose n (n / R) ≤ A.queries
  steganographic_mask :
    ∀ (P : ValidPartition n R) (r s : Fin R),
      r ≠ s → ∀ j : Fin n, j ∈ P.groups r →
      indicator (P.groups s) j = 0
  steganographic_output :
    ∀ (o : ℕ) (_ho : 0 < o)
      (h_act : Vec n) (W2 : Fin n → Fin o → ℝ) (b2 : Fin o → ℝ)
      (mask : Vec n),
      let logits := output_logits (h_act ⊙ mask) W2 b2
      (∀ k : Fin o, 0 < softmax logits k)
      ∧ (∑ k : Fin o, softmax logits k = 1)
  weight_indistinguishable :
    ∀ (m o : ℕ) (S : CryptoScheme n R) (T : TrainingProcess n R m o),
      IsSurjective T →
      ∀ (W : ModelWeights m n o) (k : S.Key),
        ∃ D : T.Data, T.train (S.derive k) D = W
  regime_locality :
    ∀ (o : ℕ) (P : ValidPartition n R) (s : Fin R)
      (h_act : Vec n) (W2 : Fin n → Fin o → ℝ) (b2 : Fin o → ℝ),
      ∀ k : Fin o,
        output_logits (h_act ⊙ indicator (P.groups s)) W2 b2 k =
        (P.groups s).sum (fun j => h_act j * W2 j k) + b2 k
  exact_mask :
    ∀ (P : ValidPartition n R) (r : Fin R) (M : Vec n),
      (∀ (o : ℕ) (h_act : Vec n) (W2 : Fin n → Fin o → ℝ)
        (b2 : Fin o → ℝ) (k : Fin o),
          output_logits (h_act ⊙ M) W2 b2 k =
          output_logits (h_act ⊙ indicator (P.groups r)) W2 b2 k) →
      ∀ j : Fin n, M j = indicator (P.groups r) j
  compositional_confinement :
    ∀ (mask : Vec n) (j : Fin n),
      mask j = 0 → ∀ upstream : ℝ, upstream * mask j = 0

theorem standard_is_distributable_safe_v3
    (h_enumeration : FullEnumerationAssumption 768 2) :
    DistributableSafetyV3 768 2 where
  combinatorial_hardness := standard_support_count_ge_two_pow_256
  no_shortcut := h_enumeration
  steganographic_mask := fun P r s hrs j hj =>
    wrong_mask_reads_wrong_dims P r s hrs j hj
  steganographic_output := fun o ho h_act W2 b2 mask =>
    ⟨fun k => softmax_pos ho _ k, softmax_sum_one ho _⟩
  weight_indistinguishable := fun _ _ S T hT =>
    zero_key_information S T hT
  regime_locality := fun o P s h_act W2 b2 =>
    regime_output_locality P s h_act W2 b2
  exact_mask := fun P r M h_same =>
    access_requires_exact_mask P r M h_same
  compositional_confinement := fun mask j hj upstream => by
    rw [hj, mul_zero]

theorem end_to_end_chain_v3
    (h_enumeration : FullEnumerationAssumption 768 2) :
    DistributableSafetyV3 768 2 :=
  standard_is_distributable_safe_v3 h_enumeration

end Schemen.SecurityV3
