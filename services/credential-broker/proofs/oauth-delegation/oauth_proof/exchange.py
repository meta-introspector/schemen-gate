"""RFC 8693 + RFC 9396 + RFC 9449 composition under a closed local policy."""

from __future__ import annotations

import secrets
import time
from typing import Any

from credential_broker import call_gate

from .authority import Authority, Grant
from .jose import access
from .profile import (
    ACCESS_TYPE,
    EXCHANGE,
    ISSUER,
    JWT_TYPE,
    RESOURCE,
    TOKEN_URL,
    details,
    loads,
    require,
)

GATE_CLAIM = "urn:schemen:proof:gate"


def contract(root: str, actor: str, value: Any, connection: str = "calendar-v1") -> dict[str, Any]:
    return {
        "tenant": "proof-tenant",
        "root": root,
        "subject": "owner",
        "actor": actor,
        "connection": connection,
        "channel": "registered-session",
        "audience": RESOURCE,
        "uses": 1,
        "authorization_details": value,
        "response_policy": "event-id-only",
    }


def exchange(
    authority: Authority, client: str, form: dict[str, str], proof: str, actual_url: str = TOKEN_URL
) -> dict[str, Any]:
    with authority.lock:
        required = {
            "grant_type",
            "subject_token",
            "subject_token_type",
            "actor_token",
            "actor_token_type",
            "requested_token_type",
            "resource",
            "authorization_details",
        }
        require(set(form) == required, "invalid_request")
        require(form["grant_type"] == EXCHANGE, "unsupported_grant_type")
        require(
            form["subject_token_type"] in {JWT_TYPE, ACCESS_TYPE}
            and form["actor_token_type"] == JWT_TYPE
            and form["requested_token_type"] == ACCESS_TYPE,
            "invalid_request",
        )
        require(form["resource"] == RESOURCE, "invalid_target")
        now = int(time.time())
        parent = access(form["subject_token"], authority.key, RESOURCE, now)
        actor = access(form["actor_token"], authority.key, ISSUER, now)
        require(actor["sub"] == client and client in authority.principals)
        principal = authority.principals[client]
        require(actor.get("cnf") == {"jkt": principal.key_thumbprint})
        thumb = authority.proofs.verify(
            proof,
            "POST",
            actual_url,
            nonce=authority.nonces["token"],
            expected_key=principal.key_thumbprint,
        )
        require(type(parent.get("jti")) is str and parent["jti"] in authority.grants)
        previous = authority.grants[parent["jti"]]
        pending = authority.pending[previous.root]
        require(not pending.revoked and not pending.dispatched and now < pending.expires)
        require(parent["sub"] == "owner")
        current = parent.get("act", {"sub": parent["sub"]})
        require(type(current) is dict and current.get("sub") == previous.actor)
        require(parent.get("may_act") == {"sub": client} and previous.next_actor == client)
        require(previous.actor in pending.approved and not previous.exchanged)
        requested = details(loads(form["authorization_details"]))
        require(
            requested == pending.authorization_details == parent.get("authorization_details"),
            "invalid_authorization_details",
        )
        expiry = min(parent["exp"], actor["exp"], pending.expires, now + 60)
        identifier = secrets.token_urlsafe(24)
        current_actor: dict[str, Any] = {"sub": client}
        if "act" in parent:
            current_actor["act"] = parent["act"]  # History only; never consulted for permission.
        next_actor = "worker" if client == "reviewer" else None
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": RESOURCE,
            "sub": parent["sub"],
            "client_id": client,
            "iat": now,
            "exp": expiry,
            "jti": identifier,
            "act": current_actor,
            "cnf": {"jkt": thumb},
            "authorization_details": requested,
            GATE_CLAIM: call_gate.issue(
                authority.gate_key, contract(previous.root, client, requested), expiry
            ),
        }
        if next_actor:
            claims["may_act"] = {"sub": next_actor}
        encoded = authority.sign(claims)
        authority.grants[identifier] = Grant(previous.root, client, next_actor)
        previous.exchanged = True
        return {
            "access_token": encoded,
            "issued_token_type": ACCESS_TYPE,
            "token_type": "DPoP",
            "expires_in": expiry - now,
            "authorization_details": requested,
        }


def execute(
    authority: Authority,
    token: str,
    proof: str,
    body: Any,
    connection: str = "calendar-v1",
    actual_url: str = RESOURCE,
) -> dict[str, Any]:
    with authority.lock:
        claims = access(token, authority.key, RESOURCE, int(time.time()))
        require(type(claims.get("jti")) is str and claims["jti"] in authority.grants)
        row = authority.grants[claims["jti"]]
        pending = authority.pending[row.root]
        require(not pending.revoked and not pending.dispatched and time.time() < pending.expires)
        require(row.next_actor is None and row.actor == "worker")
        require(claims.get("act", {}).get("sub") == row.actor and claims["sub"] == "owner")
        expected = authority.principals[row.actor].key_thumbprint
        require(claims.get("cnf") == {"jkt": expected})
        authority.proofs.verify(
            proof,
            "POST",
            actual_url,
            nonce=authority.nonces["resource"],
            expected_key=expected,
            access_token=token,
        )
        require(type(body) is dict and set(body) == {"call"}, "invalid_request")
        granted = claims["authorization_details"]
        actual = details([{**granted[0], "call": body["call"]}])
        # DPoP has no body binding. This invokes the real broker Gate adapter against actual input.
        call_gate.authenticate(
            authority.gate_key,
            claims[GATE_CLAIM],
            contract(row.root, row.actor, actual, connection),
            claims["exp"],
        )
        require(actual == pending.authorization_details, "invalid_authorization_details")
        pending.dispatched = True  # Shared root budget, consumed before the counted effect.
        authority.provider_calls.append(body["call"])
        return {"event_id": body["call"]["event"]["id"]}
