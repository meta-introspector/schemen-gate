"""Independent PyJWT client; no reuse of the server's signing or proof helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from oauth_proof.authority import Authority, Principal
from oauth_proof.http import app
from oauth_proof.profile import (
    ACCESS_TYPE,
    EXCHANGE,
    ISSUER,
    JWT_TYPE,
    RAR_TYPE,
    RESOURCE,
    TOKEN_URL,
)


def sha(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode().rstrip("=")


class ClientKey:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key()))
        self.thumb = sha(
            json.dumps(
                {k: self.public[k] for k in ("crv", "kty", "x", "y")},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )

    def proof(
        self, url: str, server_nonce: str | None, token: str | None = None, **changes: Any
    ) -> str:
        payload: dict[str, Any] = {
            "jti": secrets.token_urlsafe(24),
            "htm": "POST",
            "htu": url,
            "iat": int(time.time()),
        }
        if server_nonce is not None:
            payload["nonce"] = server_nonce
        if token is not None:
            payload["ath"] = sha(token.encode("ascii"))
        payload.update(changes)
        return jwt.encode(
            payload, self.key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": self.public}
        )


CALL = {
    "calendar_id": "primary",
    "send_updates": "none",
    "event": {
        "id": "abcde12345",
        "summary": "One approved event",
        "start": {"dateTime": "2026-09-10T17:00:00Z"},
        "end": {"dateTime": "2026-09-10T17:30:00Z"},
    },
}
DETAILS = [{"type": RAR_TYPE, "actions": ["create"], "locations": [RESOURCE], "call": CALL}]


class Harness:
    def __init__(self, reviewer_kind: str = "agent") -> None:
        self.keys = {p: ClientKey() for p in ("owner", "reviewer", "worker", "outsider")}
        self.authority = Authority(
            {
                p: Principal(
                    p,
                    reviewer_kind if p == "reviewer" else "agent",
                    key.thumb,
                    secrets.token_urlsafe(24),
                )
                for p, key in self.keys.items()
            }
        )
        self.http = TestClient(app(self.authority), base_url=ISSUER)
        self.root = self.authority.request(DETAILS)

    def decide(self, who: str, allow: bool = True) -> None:
        self.authority.decide(self.root, self.authority.principals[who], allow)

    def form(self, parent: str, actor: str) -> dict[str, str]:
        return {
            "grant_type": EXCHANGE,
            "subject_token": parent,
            "subject_token_type": JWT_TYPE,
            "actor_token": self.authority.actor_token(actor),
            "actor_token_type": JWT_TYPE,
            "requested_token_type": ACCESS_TYPE,
            "resource": RESOURCE,
            "authorization_details": json.dumps(DETAILS),
        }

    def exchange(
        self,
        parent: str,
        actor: str,
        *,
        form: dict[str, str] | None = None,
        proof: str | None = None,
        auth_actor: str | None = None,
    ) -> Any:
        caller = auth_actor or actor
        authorization = (
            "Basic "
            + base64.b64encode(
                f"{caller}:{self.authority.principals[caller].client_secret}".encode()
            ).decode()
        )
        return self.http.post(
            TOKEN_URL,
            data=self.form(parent, actor) if form is None else form,
            headers={
                "Authorization": authorization,
                "DPoP": proof or self.keys[actor].proof(TOKEN_URL, self.authority.nonces["token"]),
            },
        )

    def root_token(self) -> str:
        self.decide("owner")
        return self.authority.root_token(self.root)

    def ready(self) -> str:
        first = self.exchange(self.root_token(), "reviewer")
        assert first.status_code == 200, first.text
        self.decide("reviewer")
        second = self.exchange(first.json()["access_token"], "worker")
        assert second.status_code == 200, second.text
        return second.json()["access_token"]

    def execute(
        self, token: str, *, call: Any = None, proof: str | None = None, scheme: str = "DPoP"
    ) -> Any:
        return self.http.post(
            RESOURCE,
            json={"call": CALL if call is None else call},
            headers={
                "Authorization": f"{scheme} {token}",
                "DPoP": proof
                or self.keys["worker"].proof(RESOURCE, self.authority.nonces["resource"], token),
            },
        )


@pytest.fixture
def h() -> Harness:
    return Harness()
