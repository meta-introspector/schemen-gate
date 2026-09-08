"""Explicit approval fixtures and a two-hop policy, deliberately outside OAuth wire flow."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from joserfc import jwt
from joserfc.jwk import ECKey

from .jose import Proofs
from .profile import ISSUER, RESOURCE, details, require


@dataclass(frozen=True)
class Principal:
    subject: str
    kind: str  # Display metadata; human/agent has no implicit authorization effect.
    key_thumbprint: str
    client_secret: str


@dataclass
class Pending:
    authorization_details: list[dict[str, Any]]
    expires: int
    approved: set[str]
    revoked: bool = False
    dispatched: bool = False


@dataclass
class Grant:
    root: str
    actor: str
    next_actor: str | None
    exchanged: bool = False


class Authority:
    def __init__(self, principals: dict[str, Principal]) -> None:
        self.principals = principals
        self.key = ECKey.generate_key("P-256")
        self.gate_key = secrets.token_bytes(32)
        self.lock = threading.RLock()
        self.proofs = Proofs()
        self.nonces = {"token": secrets.token_urlsafe(24), "resource": secrets.token_urlsafe(24)}
        self.pending: dict[str, Pending] = {}
        self.grants: dict[str, Grant] = {}
        self.provider_calls: list[dict[str, Any]] = []

    def request(self, value: Any) -> str:
        with self.lock:
            root = secrets.token_urlsafe(24)
            self.pending[root] = Pending(details(value), int(time.time()) + 120, set())
            return root

    def decide(self, root: str, authenticated: Principal, approve: bool) -> None:
        """Trusted identity fixture, not an exposed principal-string approval API."""
        with self.lock:
            require(self.principals.get(authenticated.subject) is authenticated)
            pending = self.pending[root]
            require(
                not pending.revoked and not pending.dispatched and time.time() < pending.expires
            )
            require(authenticated.subject in {"owner", "reviewer"})
            if authenticated.subject == "reviewer":
                require("owner" in pending.approved)
                require(any(g.root == root and g.actor == "reviewer" for g in self.grants.values()))
            require(authenticated.subject not in pending.approved)
            if approve:
                pending.approved.add(authenticated.subject)
            else:
                pending.revoked = True

    def sign(self, claims: dict[str, Any]) -> str:
        return jwt.encode({"alg": "ES256", "typ": "JWT"}, claims, self.key)

    def actor_token(self, subject: str) -> str:
        now = int(time.time())
        return self.sign(
            {
                "iss": ISSUER,
                "aud": ISSUER,
                "sub": subject,
                "iat": now,
                "exp": now + 120,
                "cnf": {"jkt": self.principals[subject].key_thumbprint},
            }
        )

    def root_token(self, root: str) -> str:
        with self.lock:
            p = self.pending[root]
            require("owner" in p.approved and not p.revoked and time.time() < p.expires)
            identifier = secrets.token_urlsafe(24)
            self.grants[identifier] = Grant(root, "owner", "reviewer")
            return self.sign(
                {
                    "iss": ISSUER,
                    "aud": RESOURCE,
                    "sub": "owner",
                    "iat": int(time.time()),
                    "exp": p.expires,
                    "jti": identifier,
                    "may_act": {"sub": "reviewer"},
                    "authorization_details": p.authorization_details,
                }
            )
