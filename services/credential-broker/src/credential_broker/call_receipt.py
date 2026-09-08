"""Publicly verifiable local disposition, checked against a pinned issuer key."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .models import BrokerError, canonical

DOMAIN = b"schemen/calendar-call-receipt-v1\x00"


def public_key(key: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes_raw().hex()


def sign_receipt(key: bytes, body: dict[str, Any]) -> dict[str, Any]:
    signature = Ed25519PrivateKey.from_private_bytes(key).sign(DOMAIN + canonical(body))
    return {"body": body, "signature": signature.hex()}


def verify_receipt(
    receipt: dict[str, Any],
    expected_key: str,
    grant_id: str,
    aad_sha256: str,
) -> dict[str, Any]:
    try:
        if set(receipt) != {"body", "signature"}:
            raise ValueError()
        body = receipt["body"]
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected_key)).verify(
            bytes.fromhex(receipt["signature"]), DOMAIN + canonical(body)
        )
        if (
            body["schema"] != "schemen/calendar-call-receipt-v1"
            or body["grant_id"] != grant_id
            or body["aad_sha256"] != aad_sha256
            or body["authority"] != "consumed"
            or body["credential_custody"] != "destroyed"
        ):
            raise ValueError()
        return dict(body)
    except Exception:
        raise BrokerError(403, "invalid_call_receipt") from None
