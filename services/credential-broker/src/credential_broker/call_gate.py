"""Bind one broker call to public Gate AAD; durable consumption belongs to the vault."""

from __future__ import annotations

import hashlib
import importlib
import math
import time
from types import ModuleType
from typing import TYPE_CHECKING, Any, cast

from .models import BrokerError, canonical

if TYPE_CHECKING:
    from schemen_gate import GateKey, OperationTransitionAAD

DOMAIN = "schemen/credential-broker-call-gate-v1"


def _gate() -> ModuleType:
    try:
        return importlib.import_module("schemen_gate")
    except ImportError:
        raise BrokerError(503, "call_gate_unavailable") from None


def _json(value: object) -> None:
    """Reject Python coercions that would collapse distinct contracts into JSON."""
    if value is None or type(value) in {str, bool, int, float}:
        return
    if type(value) is list:
        for item in value:
            _json(item)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _json(item)
        return
    raise ValueError("contract must contain exact JSON values")


def _parts(
    gate: ModuleType, authority_key: bytes, contract: dict[str, Any], expires_at: float
) -> tuple[GateKey, OperationTransitionAAD, int]:
    if type(contract) is not dict or type(contract.get("tenant")) is not str:
        raise ValueError("tenant contract required")
    if not contract["tenant"] or "\x00" in contract["tenant"]:
        raise ValueError("tenant contract required")
    if type(expires_at) not in {int, float} or not math.isfinite(expires_at):
        raise ValueError("finite expiry required")
    expiry = float(expires_at)
    if expiry <= time.time():
        raise ValueError("grant expired")
    _json(contract)
    seal = hashlib.sha256(canonical({"contract": contract, "expires_at": expiry})).hexdigest()
    tenant_seal = hashlib.sha256(canonical({"tenant": contract["tenant"]})).hexdigest()
    language = f"{DOMAIN}:{tenant_seal}"
    key = gate.derive_operation_gate_key(gate.GateKey(authority_key), language)
    aad = gate.OperationTransitionAAD(
        language_id=language,
        language_seal=DOMAIN,
        machine_id=DOMAIN,
        machine_seal=DOMAIN,
        decoder_id="canonical-json-sha256",
        decoder_seal=DOMAIN,
        c_rasp_decision_seal=DOMAIN,
        c_rasp_status="NOT_APPLICABLE_NATIVE_CALL",
        route_seal=seal,
        route_disposition=gate.NATIVE_ROUTE,
        native_executor_id=DOMAIN,
        learned_proposer_id="none",
        proposal_origin=gate.OperationProposalOrigin.NATIVE_EXACT,
        source_state="authorized",
        source_snapshot_seal=seal,
        operation_symbol="dispatch-http-once",
        target_state="consumed",
        target_snapshot_seal=seal,
        transition_id=seal,
        transition_seal=seal,
        sequence=1,
        operation_target=seal,
        arguments_sha256=seal,
        required_conditions=("durable-consumption-before-dispatch",),
    )
    # Gate uses integer epochs; the independently authenticated fractional expiry
    # above remains authoritative and is checked before every authentication.
    return key, aad, math.ceil(expiry)


def issue(authority_key: bytes, contract: dict[str, Any], expires_at: float) -> dict[str, Any]:
    """Issue an exact-call token; caller must first authorize the complete contract."""
    gate = _gate()
    try:
        key, aad, epoch = _parts(gate, authority_key, contract, expires_at)
        token = gate.issue_operation_gate(key, aad, issuer_context=DOMAIN, expires_epoch=epoch)
        return cast(dict[str, Any], token.to_dict())
    except Exception:
        raise BrokerError(403, "call_gate_invalid") from None


def authenticate(
    authority_key: bytes,
    token: dict[str, Any],
    contract: dict[str, Any],
    expires_at: float,
) -> None:
    """Authenticate actual call context; this function does not consume a token."""
    gate = _gate()
    try:
        key, aad, epoch = _parts(gate, authority_key, contract, expires_at)
        parsed = gate.OperationGateToken.from_dict(token)
        if parsed.issuer_context != DOMAIN or parsed.expires_epoch != epoch:
            raise ValueError("grant metadata mismatch")
        gate.authenticate_operation_gate(parsed, key, expected_contract=aad)
    except Exception:
        raise BrokerError(403, "call_gate_invalid") from None
