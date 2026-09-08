"""Standard token exchange fields, private_key_jwt client authentication, and DPoP."""

from __future__ import annotations

import secrets
import time
from typing import Any

from credential_broker import call_gate

from ._profile import ACCESS_TYPE, EXCHANGE, JWT_TYPE, Denied, details, loads, require
from .crypto import check_dpop, valid, verify
from .execution import NonceRequired
from .service import ACCESS, ACTOR, CALLBACK, Service

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def redeem(service: Service, form: dict[str, str], proof: str) -> dict[str, Any]:
    fields = {
        "grant_type",
        "subject_token",
        "subject_token_type",
        "actor_token",
        "actor_token_type",
        "requested_token_type",
        "resource",
        "authorization_details",
        "client_id",
        "client_assertion_type",
        "client_assertion",
    }
    require(set(form) == fields, "invalid_request")
    require(form["grant_type"] == EXCHANGE, "unsupported_grant_type")
    require(
        form["subject_token_type"] == JWT_TYPE
        and form["actor_token_type"] == JWT_TYPE
        and form["requested_token_type"] == ACCESS_TYPE
        and form["client_assertion_type"] == ASSERTION_TYPE,
        "invalid_request",
    )
    require(form["resource"] == service.config.resource, "invalid_target")
    callback, _ = verify(form["subject_token"], CALLBACK, expected=service.signing_key)
    with service.store.transaction() as db:
        row = service.store.load(db, callback.get("request_id"))
        require(row["status"] == "approved" and time.time() < row["expires"])
        valid(callback, service.config.issuer, row["callback_url"])
        require(form["subject_token"] == row["callback"] and callback["decision"] == "approve")
        actor, _ = verify(form["actor_token"], ACTOR, expected=service.signing_key)
        valid(actor, service.config.issuer, service.config.issuer)
        require(form["actor_token"] == row["actor"] and actor["sub"] == row["caller"])
        auth, key = verify(form["client_assertion"], "JWT")
        require(
            key == row["caller"] == form["client_id"] and auth.get("sub") == key, "invalid_client"
        )
        valid(auth, key, service.config.issuer + "/token", maximum=60)
        require(set(auth) == {"iss", "sub", "aud", "iat", "exp", "jti"}, "invalid_client")
        try:
            identifier, proof_expiry = check_dpop(
                proof, service.config.issuer + "/token", row["nonce"], key
            )
        except Denied as exc:
            if exc.code == "use_dpop_nonce":
                raise NonceRequired(row["nonce"]) from None
            raise
        requested = details(loads(form["authorization_details"]), resource=service.config.resource)
        require(requested == row["details"], "invalid_authorization_details")
        service.store.replay(db, "client-auth:" + key, auth["jti"], auth["exp"])
        service.store.replay(db, "dpop:" + key, identifier, proof_expiry)
        expiry = min(row["expires"], int(time.time()) + 60)
        claims = {
            "sub": service.config.tenant,
            "client_id": key,
            "act": {"sub": key},
            "cnf": {"jkt": key},
            "request_id": row["id"],
            "authorization_details": requested,
            "urn:schemen:gate": call_gate.issue(
                service.gate_key, service.contract(row, requested), expiry
            ),
        }
        token = service.signed(ACCESS, service.config.resource, expiry, claims)
        row.update(
            status="issued",
            access_token=token,
            access_expires=expiry,
            execution_nonce=secrets.token_urlsafe(24),
        )
        service.store.save(db, row)
        return {
            "access_token": token,
            "issued_token_type": ACCESS_TYPE,
            "token_type": "DPoP",
            "expires_in": expiry - int(time.time()),
            "authorization_details": requested,
        }
