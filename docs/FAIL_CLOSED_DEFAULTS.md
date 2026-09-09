# Fail-closed defaults

Schemen Gate distinguishes cryptographic integrity from authorization. A
signature made by an object-carried key can prove that the object is internally
consistent; it cannot prove that the signer is trusted. Public verification
therefore requires verifier-owned identity and scope.

## Authority verification

- `verify_delegation` requires `expected_da_public_key`.
- `verify_attestation` requires `expected_runtime_public_key`.
- `verify_operation_public_attestation` requires
  `expected_signer_public_key`.
- The corresponding `*_self_consistency` functions are historical inspection
  tools. They do not return an authorization decision.
- Enforced attestation verification additionally binds the expected action,
  target, capability reference, success value, and bounded execution time.

## Lifetimes and permissions

- Adapter and exact-operation issuance assigns a one-hour lifetime when expiry
  is omitted.
- A non-expiring adapter or operation credential requires both
  `expires_epoch=None` and `allow_non_expiring=True`.
- `GateRights` grants no permissions when permission bits are omitted and has a
  finite default lifetime.
- Cargo manifests receive a one-hour default lifetime. Passing
  `ttl_seconds=None` is the explicit non-expiring construction.
- Mask tokens intentionally remain static-key artifacts without an embedded
  clock. Their lifetime is governed by Gate-key rotation, lockbox custody, and
  the surrounding deployment policy.

## Scope and storage

- Once `SkillRegistry` is configured with a Gate, every registered skill and
  every dispatch—including `dispatch_top_k`—requires an exact Regime. Only
  skills registered to that Regime are eligible; absent eligible skills fail
  closed, and nonfinite embeddings are rejected before normalization.
- `PartitionMap.register` defaults to `IMMUTABLE`; write authority must be
  selected explicitly.
- Cargo manifest schema v7 binds `gate_embeddings_at_rest` as authenticated
  policy.
- Direct `GatedRAGAdapter.ingest` and `ingest_many` calls require the caller to
  select `gate_embedding=True` or `False`. Inference gating does not imply that
  stored vectors were gated.

## Activation selection

`GateMask.apply`, the optional PyTorch layer, and the C++ primitive select
positive zero for excluded coordinates even when their input or incoming
Torch gradient is NaN/Inf. Active values remain unchanged. This is a local
execution boundary, not a whole-graph nonfinite sanitizer or optimizer policy.
NumPy retains its float64-mask dtype promotion; unsupported masked/nonnumeric
arrays and multiplication-only backends are rejected explicitly.

## Imported metadata and identity

- Imported Gate-mask documents require `regime_id`. File imports may receive it
  from the caller or the mask sidecar.
- Inference-stream wire documents require `frame_index` and `is_final`; the
  parser does not invent either value.
- A clean source checkout is bound to its exact Git `HEAD`. Installed release
  archives use the generated build stamp. Tracked, staged, or non-ignored
  untracked drift fails closed.
- `SpiffeWorkloadClient.fetch_identity(validate_spiffe_id_syntax=True)` names
  its limited check precisely. Full path, key-match, validity, and trust-domain
  verification is required before the identity crosses an authority boundary.
- A network-capable revocation policy requires a nonempty exact-host allowlist.

## Compatibility rule

These changes reject calls whose omitted inputs previously widened authority.
That tightening is a security correction under the 1.x API stability contract,
not a new cryptographic method. Existing callers must supply the authority,
scope, or policy they already intended.
