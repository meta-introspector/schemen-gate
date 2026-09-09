import GatePlacement
import CompressionSecurity
import GenerationIsolation

/-!
This file is an executable audit receipt, not an additional proof module.
`lake env lean scripts/lean_claim_audit.lean` prints the transitive axiom set
for the paper's headline algebraic theorems. The release check rejects any
project-specific axiom name in this output.
-/

#print axioms Schemen.forward_isolation
#print axioms Schemen.gradient_isolation
#print axioms Schemen.gradient_confinement
#print axioms Schemen.active_preserves
#print axioms Schemen.weight_update_confined
#print axioms Schemen.w2_update_confined
#print axioms Schemen.SecurityV3.residual_block_full_confinement
#print axioms Schemen.SecurityV3.non_preserving_breaks_w1_confinement
#print axioms Schemen.CompressionSecurity.injection_confined_vec
#print axioms Schemen.Security.standard_support_count_ge_two_pow_256
#print axioms Schemen.SecurityV2.gated_output_valid_distribution
#print axioms Schemen.SecurityV3.regime_output_independent_of_others
#print axioms Schemen.Generation.autoregressive_independent_of_inactive
