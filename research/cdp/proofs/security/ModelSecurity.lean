/-
Copyright (c) 2026 Ryan R. All rights reserved.
Released under Apache 2.0; see LICENSES/Apache-2.0.txt.
Authors: Ryan R
-/


import GateSecurity
import Mathlib.Data.Nat.Choose.Sum

-- These proofs intentionally reduce concrete powers up to 2^384.
set_option exponentiation.threshold 512

/-!
# Partition Cardinality and Local Confinement

The results prove binomial cardinality bounds and modeled coordinate/update
properties. They do not prove recovery cost, key entropy, confidentiality of
trained weights, or an AES-comparable security level.

`search_space` counts all supports of the declared size. Python derives masks
from exactly 32 key bytes; deterministic expansion does not add key entropy.
The historical wrapper theorems now require an explicit, unvalidated
`FullEnumerationAssumption`. No PRF reduction establishes that premise here.
Historical names referring to security, extraction, or physical infeasibility
are compatibility names for narrower arithmetic/algebraic statements.
-/

set_option autoImplicit false

namespace Schemen.Security

open Schemen


-- ════════════════════════════════════════════════════════════════
-- §A. ABSTRACT PARTITION DERIVATION
-- ════════════════════════════════════════════════════════════════

/-- A deterministic function into valid partitions. This structure contains
    no PRF game or key distribution. `key_space_bits` is metadata, not a
    proved cardinality of `Key`. -/
structure CryptoScheme (n R : ℕ) where
  Key : Type
  derive : Key → ValidPartition n R
  key_space_bits : ℕ

/-- LEMMA (Determinism).
    The derivation is a pure function: same key → same partition.
    Trivially satisfied by any Lean function.
    
    Cryptographic basis: Any PRF is deterministic by definition.
    Any shuffle algorithm is deterministic given its random source.
    The full chain K → PRF → shuffle → partition is deterministic.
    
    Patent consequence: Facet 2 (dual-phase consistency).
    The mask at training time equals the mask at inference time. -/
theorem derivation_deterministic {n R : ℕ}
    (S : CryptoScheme n R) (k : S.Key) :
    S.derive k = S.derive k := rfl

-- AXIOM (REMOVED) — prf_implies_no_shortcut.
--
-- Previous versions of this file contained an axiom named
-- `prf_implies_no_shortcut` whose type was `C(n, n/R) ≤ C(n, n/R)`,
-- i.e. `le_refl`. It was a tautology and constrained nothing. It
-- was removed in the April 2026 adversarial review.
--
-- V2's global recovery axiom has also been removed. Historical consumers
-- must supply FullEnumerationAssumption; no PRF reduction is provided.

-- AXIOM (REMOVED) — training_data_private.
--
-- Previous versions of this file contained an axiom of type `True`.
-- It was removed in the April 2026 adversarial review. The intended
-- operational premise — the adversary does not possess regime-specific
-- training data — is real but lives outside the proof system. It is
-- documented in `docs/executive-summary.md` and `docs/compliance-mapping.md`
-- as a deployment requirement, not as a formal constraint.


-- ════════════════════════════════════════════════════════════════
-- §B. SUPPORT-SPACE CARDINALITY
--
-- "For N=768, R=2: the combinatorial search space is
--  C(768, 384) ≈ 10^230, log2 cardinality about 762.881; not key entropy."
--
-- We prove the exponential lower bound C(2k, k) ≥ 2^k from
-- first principles using induction and Pascal's rule.
-- No external lemmas required — pure mathematics.
-- ════════════════════════════════════════════════════════════════

/-- Monotonicity of binomial coefficients in the upper index:
    C(n, k) ≤ C(n+1, k).
    Adding one more element to choose from can only increase
    (or maintain) the count. -/
theorem choose_mono_n (n k : ℕ) :
    Nat.choose n k ≤ Nat.choose (n + 1) k := by
  cases k with
  | zero => simp
  | succ k =>
    rw [Nat.choose_succ_succ]
    exact Nat.le_add_left _ _

/-- **Theorem (Central Binomial Lower Bound). [Facet 7]**
    C(2k, k) ≥ 2^k for all k ≥ 0.

    The nominal support count grows exponentially with hidden dimension.
    A lower bound on attack cost does not follow.

    Proof by induction:
      Base: C(0, 0) = 1 ≥ 1 = 2⁰. ✓
      Step: Assume C(2k, k) ≥ 2^k.
        By Pascal:     C(2k+2, k+1) = C(2k+1, k) + C(2k+1, k+1)
        By symmetry:   C(2k+1, k+1) = C(2k+1, k)
        Therefore:     C(2k+2, k+1) = 2 · C(2k+1, k)
        By monotonicity: C(2k+1, k) ≥ C(2k, k) ≥ 2^k
        Therefore:     C(2k+2, k+1) ≥ 2 · 2^k = 2^(k+1). ∎ -/
theorem central_binom_lower (k : ℕ) : 2 ^ k ≤ Nat.choose (2 * k) k := by
  induction k with
  | zero => simp
  | succ k ih =>
    -- Rewrite goal to expose Pascal's rule structure
    have h_eq : 2 * (k + 1) = (2 * k + 1) + 1 := by omega
    rw [h_eq, Nat.choose_succ_succ]
    -- C(2k+1, k+1) = C(2k+1, k) by symmetry of binomial coefficients
    have h_symm : Nat.choose (2 * k + 1) (k + 1) =
                  Nat.choose (2 * k + 1) k := by
      have := Nat.choose_symm (show k + 1 ≤ 2 * k + 1 by omega)
      simp only [show (2 * k + 1) - (k + 1) = k from by omega] at this
      exact this.symm
    rw [h_symm]
    -- Goal: 2^(k+1) ≤ C(2k+1, k) + C(2k+1, k)
    -- From IH: 2^k ≤ C(2k, k), and C(2k, k) ≤ C(2k+1, k)
    have h_mono : Nat.choose (2 * k) k ≤ Nat.choose (2 * k + 1) k :=
      choose_mono_n (2 * k) k
    have h_pow : 2 ^ (k + 1) = 2 * 2 ^ k := by ring
    linarith

/-- Generalized monotonicity: C(m, k) ≤ C(n, k) for m ≤ n.
    Larger populations yield more combinations. -/
theorem choose_mono_n_gen (k m n : ℕ) (h : m ≤ n) :
    Nat.choose m k ≤ Nat.choose n k := by
  obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le h
  clear h
  induction d with
  | zero => simp
  | succ d ih => exact le_trans ih (choose_mono_n _ k)

/-- **Theorem (Tight Lower Bound).**
    C(2k, k) · (2k + 1) ≥ 4^k.

    Proof: ∑_{i=0}^{2k} C(2k, i) = 4^k (binomial theorem).
    C(2k, k) is the maximum term. There are 2k+1 terms.
    So (2k+1) · max ≥ sum = 4^k.

    This gives C(2k, k) ≥ 4^k/(2k+1), which is the standard
    tight asymptotic bound. For k=384: C(768,384) ≥ 2^768/769. -/
theorem central_binom_tight (k : ℕ) :
    4 ^ k ≤ Nat.choose (2 * k) k * (2 * k + 1) := by
  have h := Nat.four_pow_le_two_mul_add_one_mul_central_binom k
  linarith


-- ════════════════════════════════════════════════════════════════
-- §C. SUPPORT-COUNT PARAMETERS
-- ════════════════════════════════════════════════════════════════

/-- Historical name for dimension/regime parameters. It encodes neither
    adversary observations nor secrecy of the weights, data, or key. -/
structure AdversaryKnowledge where
  n_dims : ℕ
  n_regimes : ℕ
  hn : 0 < n_dims
  hr : 2 ≤ n_regimes
  hdiv : n_regimes ∣ n_dims

/-- Candidate supports for one regime, not a concrete key derivation's
    image size or an attack-cost bound. For R groups this is a lower bound
    on the full labeled-partition count. -/
def search_space (A : AdversaryKnowledge) : ℕ :=
  Nat.choose A.n_dims (A.n_dims / A.n_regimes)

/-- The search space is always positive. -/
theorem search_space_pos (A : AdversaryKnowledge) :
    1 ≤ search_space A :=
  Nat.choose_pos (Nat.div_le_self A.n_dims A.n_regimes)


-- ════════════════════════════════════════════════════════════════
-- §D. SEARCH SPACE BOUNDS
-- ════════════════════════════════════════════════════════════════

/-- **Theorem (Exponential Search Space — Binary Split).**
    For R=2 (two regimes), the search space is at least 2^(N/2).

    Proof: search_space = C(N, N/2) = C(2·(N/2), N/2) ≥ 2^(N/2)
    by the central binomial lower bound. -/
theorem binary_split_exponential (A : AdversaryKnowledge)
    (hR : A.n_regimes = 2) :
    2 ^ (A.n_dims / 2) ≤ search_space A := by
  unfold search_space
  rw [hR]
  have h_half := A.hdiv
  rw [hR] at h_half
  obtain ⟨m, hm⟩ := h_half
  rw [hm]
  simp only [Nat.mul_div_cancel_left m (by omega : 0 < 2)]
  exact central_binom_lower m

/-- **Theorem (General Exponential Search Space).**
    For any R, C(N, N/R) ≥ C(2·(N/R), N/R) ≥ 2^(N/R),
    as long as N ≥ 2·(N/R) (which holds when R ≥ 2). -/
theorem general_exponential_search (A : AdversaryKnowledge) :
    2 ^ (A.n_dims / A.n_regimes) ≤ search_space A := by
  unfold search_space
  set d := A.n_dims / A.n_regimes with hd_def
  -- C(2d, d) ≤ C(N, d) by monotonicity (since 2d ≤ N when R ≥ 2)
  -- 2^d ≤ C(2d, d) by central_binom_lower
  calc 2 ^ d
      ≤ Nat.choose (2 * d) d := central_binom_lower d
    _ ≤ Nat.choose A.n_dims d := by
        apply choose_mono_n_gen
        calc 2 * d
            ≤ A.n_regimes * d := Nat.mul_le_mul_right d A.hr
          _ = d * A.n_regimes := by ring
          _ ≤ A.n_dims := Nat.div_mul_le_self A.n_dims A.n_regimes


-- ════════════════════════════════════════════════════════════════
-- §E. CONCRETE CARDINALITY (N=768, R=2)
-- ════════════════════════════════════════════════════════════════

/-- Standard deployment parameters: 768-dim hidden layer, 2 regimes. -/
def standard : AdversaryKnowledge where
  n_dims := 768
  n_regimes := 2
  hn := by omega
  hr := by omega
  hdiv := ⟨384, by omega⟩

/-- C(768,384) is at least 2^384. This is a support-count bound only. -/
theorem standard_exceeds_2_384 :
    2 ^ 384 ≤ search_space standard := by
  show 2 ^ 384 ≤ Nat.choose 768 (768 / 2)
  have : (768 : ℕ) / 2 = 384 := by omega
  rw [this, show (768 : ℕ) = 2 * 384 from by omega]
  exact central_binom_lower 384

/-- The nominal support count is at least 2^256; no attack-work claim. -/
theorem standard_support_count_ge_two_pow_256 :
    2 ^ 256 ≤ search_space standard :=
  le_trans (Nat.pow_le_pow_right (by omega : 1 ≤ 2) (by omega : 256 ≤ 384))
    standard_exceeds_2_384

/-- Arithmetic factorization of the 2^384 support-count lower bound. -/
theorem standard_support_count_ge_two_pow_256_mul_two_pow_128 :
    2 ^ 256 * 2 ^ 128 ≤ search_space standard := by
  rw [← pow_add]
  exact standard_exceeds_2_384

/-- Historical compatibility name for a cardinality inequality only. -/
theorem exceeds_aes256_security :
    2 ^ 256 ≤ search_space standard :=
  standard_support_count_ge_two_pow_256

/-- Historical compatibility name; no margin in cryptographic strength. -/
theorem margin_over_aes256 :
    2 ^ 256 * 2 ^ 128 ≤ search_space standard :=
  standard_support_count_ge_two_pow_256_mul_two_pow_128

/-- Historical compatibility name. This inequality proves neither key
    entropy nor a recovery-work lower bound. -/
theorem key_is_bottleneck :
    2 ^ 256 ≤ search_space standard :=
  standard_support_count_ge_two_pow_256


-- ════════════════════════════════════════════════════════════════
-- §F. ARITHMETIC COMPARISONS WITH HISTORICAL BUDGET CONSTANTS
--
-- These inequalities compare declared integers. They do not prove
-- that an attacker must perform that many operations.
-- ════════════════════════════════════════════════════════════════

/-- Atoms in the observable universe: ≈ 10^80 ≈ 2^266. -/
def atoms_in_universe : ℕ := 2 ^ 266

/-- Generous computation rate: 1 exaflop = 10^18 ≈ 2^60 ops/sec.
    Far beyond any single machine (Frontier: ~1.2 exaflops). -/
def exaflop : ℕ := 2 ^ 60

/-- Age of the universe: ≈ 4.3 × 10^17 seconds ≈ 2^59. -/
def universe_age_sec : ℕ := 2 ^ 59

/-- Total operations achievable since the Big Bang at exaflop rate. -/
def ops_since_big_bang : ℕ := exaflop * universe_age_sec

/-- **Theorem (Single Machine Infeasibility).**
    A single exaflop computer running since the Big Bang
    would perform fewer operations than the search space.
    It would not have tested even a negligible fraction
    of the candidate partitions. -/
theorem single_machine_infeasible :
    ops_since_big_bang < search_space standard := by
  show exaflop * universe_age_sec < search_space standard
  simp only [exaflop, universe_age_sec]
  have h_ops : (2 : ℕ) ^ 60 * 2 ^ 59 = 2 ^ 119 := by ring
  rw [h_ops]
  exact lt_of_lt_of_le
    (Nat.pow_lt_pow_right (by omega : 1 < 2) (by omega : 119 < 384))
    standard_exceeds_2_384

/-- **Theorem (Universal Machine Infeasibility).**
    Even if EVERY ATOM in the observable universe were a
    processor, each running at exaflop speed, for the entire
    age of the universe — the total operations would be
    ≈ 2^385. The proven lower bound on the search space
    is 2^384, and the actual value C(768,384) ≈ 2^766. -/
theorem universal_machine_infeasible :
    atoms_in_universe * ops_since_big_bang ≤ 2 ^ 386 := by
  simp only [atoms_in_universe, ops_since_big_bang, exaflop, universe_age_sec]
  rw [← pow_add, ← pow_add]
  exact Nat.pow_le_pow_right (by omega : 1 ≤ 2) (by omega)

/-- Historical name for 2^299 < 2^384; no thermodynamic security claim. -/
theorem landauer_bound_infeasible :
    2 ^ 299 < 2 ^ 384 :=
  Nat.pow_lt_pow_right (by omega : 1 < 2) (by omega)


-- ════════════════════════════════════════════════════════════════
-- §G. LOCAL UPDATE AND MASK EXCLUSION
-- ════════════════════════════════════════════════════════════════
-- Coordinate identities do not establish opacity of trained weights.

/-- **Theorem (Column-Regime Confinement).**
    From gradient isolation (GateSecurity.lean §1-§2):
    Weight column j of W₁ was updated EXCLUSIVELY by the
    regime that owns dimension j.

    This is a consequence of `weight_update_confined`:
    if j ∉ groups(r), then d_W1[i,j] = 0 for all i.
    So column j accumulates updates only from regime assign(j).

    Whether an adversary can identify this ownership is not proved here. -/
theorem columns_are_regime_confined {n R : ℕ}
    (P : ValidPartition n R) (r : Fin R) (j : Fin n)
    (hj : j ∉ P.groups r) (d_gated relu_grad : Vec n) :
    ∀ (m' : ℕ) (x : Vec m') (i : Fin m'),
      outer x ((d_gated ⊙ indicator (P.groups r)) ⊙ relu_grad) i j = 0 :=
  fun _ x i => weight_update_confined d_gated _ relu_grad x j (indicator_not_mem _ j hj) i

/-- **Theorem (W₂ Row-Regime Confinement).**
    Row j of W₂ was updated exclusively by the regime that
    owns dimension j. If j ∉ groups(r), then d_W2[j,k] = 0
    for all output dimensions k when training under regime r.

    This is the W₂ analogue of `columns_are_regime_confined`. -/
theorem w2_rows_are_regime_confined {n R : ℕ}
    (P : ValidPartition n R) (r : Fin R) (j : Fin n)
    (hj : j ∉ P.groups r) (h : Vec n) :
    ∀ (o : ℕ) (d_logits : Vec o) (k : Fin o),
      outer (h ⊙ indicator (P.groups r)) d_logits j k = 0 :=
  fun _ d_logits k => w2_update_confined h _ d_logits j (indicator_not_mem _ j hj) k

/-- Distinct regimes of one valid partition have zero modeled updates
    and mask support on each other's coordinates. No extraction/recovery
    claim follows; different-key masks are not assumed disjoint. -/
theorem cross_regime_updates_and_mask_zero {n R : ℕ}
    (P : ValidPartition n R) (r s : Fin R) (hrs : r ≠ s)
    (d_gated relu_grad : Vec n) (h : Vec n) :
    ∀ j : Fin n, j ∈ P.groups r →
      (∀ (m' : ℕ) (x : Vec m') (i : Fin m'),
        outer x ((d_gated ⊙ indicator (P.groups s)) ⊙ relu_grad) i j = 0)
      ∧ (∀ (o : ℕ) (d_logits : Vec o) (k : Fin o),
        outer (h ⊙ indicator (P.groups s)) d_logits j k = 0)
      ∧ indicator (P.groups s) j = 0 := by
  intro j hj
  have h_not_s : j ∉ P.groups s :=
    fun hmem => hrs (unique_membership P j r s hj hmem)
  exact ⟨columns_are_regime_confined P s j h_not_s d_gated relu_grad,
         w2_rows_are_regime_confined P s j h_not_s h,
         wrong_mask_reads_wrong_dims P r s hrs j hj⟩

/-- Historical compatibility alias for local update/mask exclusion only. -/
theorem weight_extraction_requires_partition {n R : ℕ}
    (P : ValidPartition n R) (r s : Fin R) (hrs : r ≠ s)
    (d_gated relu_grad : Vec n) (h : Vec n) :
    ∀ j : Fin n, j ∈ P.groups r →
      (∀ (m' : ℕ) (x : Vec m') (i : Fin m'),
        outer x ((d_gated ⊙ indicator (P.groups s)) ⊙ relu_grad) i j = 0)
      ∧ (∀ (o : ℕ) (d_logits : Vec o) (k : Fin o),
        outer (h ⊙ indicator (P.groups s)) d_logits j k = 0)
      ∧ indicator (P.groups s) j = 0 :=
  cross_regime_updates_and_mask_zero P r s hrs d_gated relu_grad h

/-- Definitional support-count identity, not a weight-opacity claim. -/
theorem search_space_unfold (A : AdversaryKnowledge) :
    search_space A = Nat.choose A.n_dims (A.n_dims / A.n_regimes) :=
  rfl


-- ════════════════════════════════════════════════════════════════
-- §H. DISTRIBUTABLE SAFETY CLAIMS — SEE DistributableClaims.lean
--
-- The V2 `DistributableSafetyV2` structure is in DistributableClaims.lean.
-- The V1 `DistributableSafety` structure was removed in the April 2026
-- adversarial review because its `no_shortcut` field depended on the
-- tautological `prf_implies_no_shortcut` axiom (also removed).
-- ════════════════════════════════════════════════════════════════


-- ════════════════════════════════════════════════════════════════
-- §J. SCALING OF THE SUPPORT-COUNT EXPONENT
-- ════════════════════════════════════════════════════════════════

/-- Historical name for the N/R support-count exponent, not security bits. -/
def security_bits (A : AdversaryKnowledge) : ℕ :=
  A.n_dims / A.n_regimes

/-- Historical name: increasing dimension at fixed regime count grows
    the nominal support-count exponent. It does not prove stronger security. -/
theorem larger_models_more_secure
    (A₁ A₂ : AdversaryKnowledge)
    (hR : A₁.n_regimes = A₂.n_regimes)
    (hN : A₁.n_dims ≤ A₂.n_dims) :
    security_bits A₁ ≤ security_bits A₂ := by
  unfold security_bits
  rw [hR]
  exact Nat.div_le_div_right hN

/-- **Theorem.** For N=4096, R=4 (large transformer),
    the search space exceeds 2^1024.
    Uses: C(4096, 1024) ≥ C(2048, 1024) ≥ 2^1024. -/
theorem large_model_security :
    2 ^ 1024 ≤ Nat.choose 4096 1024 :=
  le_trans (central_binom_lower 1024)
    (choose_mono_n_gen 1024 (2 * 1024) 4096 (by omega))


end Schemen.Security
