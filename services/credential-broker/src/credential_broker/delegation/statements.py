"""Client-side construction; these helpers confer no authority on their own."""

from __future__ import annotations

import json
import secrets
from typing import Any

from joserfc.jwk import OKPKey

from ._profile import ACCESS_TYPE, EXCHANGE, JWT_TYPE
from .crypto import commitment, envelope, sign
from .delegation import APPROVAL, DELEGATION
from .redeem import ASSERTION_TYPE
from .service import REQUEST


def request(
    key: OKPKey,
    issuer: str,
    resource: str,
    callback_id: str,
    authorization_details: list[dict[str, Any]],
    *,
    tenant: str,
    connection: str,
) -> str:
    return sign(
        key,
        REQUEST,
        {
            **envelope(key, issuer + "/requests", ttl=300),
            "nonce": secrets.token_urlsafe(24),
            "resource": resource,
            "callback_id": callback_id,
            "authorization_details": authorization_details,
            "tenant": tenant,
            "connection": connection,
        },
    )


def delegate(
    key: OKPKey,
    delegate_key: str,
    issuer: str,
    request_hash: str,
    *,
    parent: str | None = None,
    depth: int = 0,
    ttl: int = 60,
) -> str:
    return sign(
        key,
        DELEGATION,
        {
            **envelope(key, issuer + "/approvals", ttl=ttl),
            "request_sha256": request_hash,
            "may_act": {"sub": delegate_key},
            "actions": ["approve"],
            "parent_sha256": commitment(parent) if parent else "root",
            "depth": depth,
        },
    )


def approve(
    key: OKPKey,
    issuer: str,
    request_id: str,
    request_hash: str,
    chain: list[str],
    *,
    decision: str = "approve",
    ttl: int = 60,
) -> str:
    return sign(
        key,
        APPROVAL,
        {
            **envelope(key, issuer + "/approvals", ttl=ttl),
            "request_id": request_id,
            "request_sha256": request_hash,
            "chain_sha256": commitment(chain),
            "decision": decision,
        },
    )


def exchange_form(
    key: OKPKey,
    issuer: str,
    resource: str,
    callback: str,
    actor: str,
    authorization_details: list[dict[str, Any]],
) -> dict[str, str]:
    assertion = sign(key, "JWT", {**envelope(key, issuer + "/token"), "sub": key.thumbprint()})
    return {
        "grant_type": EXCHANGE,
        "subject_token": callback,
        "subject_token_type": JWT_TYPE,
        "actor_token": actor,
        "actor_token_type": JWT_TYPE,
        "requested_token_type": ACCESS_TYPE,
        "resource": resource,
        "authorization_details": json.dumps(authorization_details),
        "client_id": key.thumbprint(),
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": assertion,
    }
