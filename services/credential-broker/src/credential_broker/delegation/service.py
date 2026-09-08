"""Durable request, signed decision, and callback issuance. No provider credentials here."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from joserfc.jwk import OKPKey

from ._profile import details, require
from .crypto import commitment, envelope, sign, valid, verify
from .delegation import approval
from .store import Store

REQUEST = "schemen-request+jwt"
PENDING = "schemen-pending+jwt"
CALLBACK = "schemen-callback+jwt"
ACTOR = "schemen-actor+jwt"
ACCESS = "at+jwt"


@dataclass(frozen=True)
class ReturnChannel:
    identifier: str
    caller_key: str
    url: str


@dataclass(frozen=True)
class Config:
    issuer: str
    resource: str
    tenant: str
    connection: str
    owner_keys: tuple[str, ...]
    channels: tuple[ReturnChannel, ...]

    def __post_init__(self) -> None:
        require(bool(self.owner_keys) and bool(self.tenant) and bool(self.connection))
        require(len({c.identifier for c in self.channels}) == len(self.channels))
        for url in (self.issuer, self.resource, *(c.url for c in self.channels)):
            parts = urlsplit(url)
            require(
                parts.scheme == "https"
                and bool(parts.hostname)
                and parts.username is None
                and parts.password is None
                and not parts.query
                and not parts.fragment
            )
        require(not self.issuer.endswith("/"))
        require(urlsplit(self.resource).path == "/calendar/execute")


class Service:
    def __init__(self, config: Config, signing_key: OKPKey, gate_key: bytes, database: Path):
        require(
            signing_key.is_private
            and signing_key.as_dict(private=False).get("crv") == "Ed25519"
            and len(gate_key) == 32
        )
        self.config, self.signing_key, self.gate_key = config, signing_key, gate_key
        self.store = Store(
            database,
            commitment(
                {
                    "issuer": config.issuer,
                    "resource": config.resource,
                    "tenant": config.tenant,
                    "connection": config.connection,
                    "roots": list(config.owner_keys),
                    "channels": [[c.identifier, c.caller_key, c.url] for c in config.channels],
                    "signer": signing_key.thumbprint(),
                    "gate": commitment(gate_key.hex()),
                }
            ),
            HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None, info=b"schemen/bound-flow-state-v1"
            ).derive(gate_key),
        )

    def signed(self, kind: str, audience: str, expiry: int, extra: dict[str, Any]) -> str:
        claims = envelope(self.signing_key, audience)
        claims.update({"iss": self.config.issuer, "exp": expiry, **extra})
        return sign(self.signing_key, kind, claims)

    def request(self, statement: str) -> dict[str, Any]:
        claims, caller = verify(statement, REQUEST)
        valid(claims, caller, self.config.issuer + "/requests")
        require(
            set(claims)
            == {
                "iss",
                "aud",
                "iat",
                "exp",
                "jti",
                "nonce",
                "callback_id",
                "authorization_details",
                "resource",
                "tenant",
                "connection",
            }
        )
        require(claims["resource"] == self.config.resource)
        require(
            claims["tenant"] == self.config.tenant
            and claims["connection"] == self.config.connection
        )
        require(type(claims["nonce"]) is str and 16 <= len(claims["nonce"]) <= 128)
        channel = next(
            (c for c in self.config.channels if c.identifier == claims["callback_id"]), None
        )
        require(channel is not None and channel.caller_key == caller, "unregistered_return_channel")
        assert channel is not None
        approved = details(claims["authorization_details"], resource=self.config.resource)
        require(approved[0]["locations"] == [self.config.resource])
        identifier = secrets.token_urlsafe(24)
        row: dict[str, Any] = {
            "id": identifier,
            "hash": commitment(claims),
            "request": statement,
            "caller": caller,
            "channel": channel.identifier,
            "callback_url": channel.url,
            "caller_nonce": claims["nonce"],
            "nonce": secrets.token_urlsafe(24),
            "expires": claims["exp"],
            "details": approved,
            "status": "pending",
        }
        actor = self.signed(
            ACTOR,
            self.config.issuer,
            row["expires"],
            {"sub": caller, "cnf": {"jkt": caller}, "request_id": identifier},
        )
        row["actor"] = actor
        with self.store.transaction() as db:
            self.store.replay(db, "request:" + caller, claims["jti"], claims["exp"])
            self.store.add(db, row)
        return {
            "pending": self.signed(
                PENDING,
                caller,
                row["expires"],
                {
                    "request_id": identifier,
                    "request_sha256": row["hash"],
                    "nonce": row["nonce"],
                    "caller_nonce": row["caller_nonce"],
                },
            ),
            "actor_token": actor,
        }

    def approve(self, request_id: str, statement: str, chain: list[str]) -> None:
        with self.store.transaction() as db:
            row = self.store.load(db, request_id)
            require(row["status"] == "pending" and time.time() < row["expires"])
            decision = approval(
                statement, chain, row, self.config.owner_keys, self.config.issuer + "/approvals"
            )
            self.store.replay(db, "approval:" + decision["iss"], decision["jti"], decision["exp"])
            row["expires"] = min(row["expires"], decision["exp"])
            row["approval"], row["chain"] = statement, chain
            row["status"] = "approved" if decision["decision"] == "approve" else "denied"
            row["callback"] = self.signed(
                CALLBACK,
                row["callback_url"],
                row["expires"],
                {
                    "sub": self.config.tenant,
                    "request_id": row["id"],
                    "request_sha256": row["hash"],
                    "caller_nonce": row["caller_nonce"],
                    "cnf": {"jkt": row["caller"]},
                    "resource": self.config.resource,
                    "decision": decision["decision"],
                    "approval_sha256": commitment({"statement": statement, "chain": chain}),
                    "may_act": {"sub": row["caller"]},
                },
            )
            self.store.save(db, row)

    def callback(self, request_id: str) -> tuple[str, str]:
        """Trusted outbox interface, not a public unauthenticated lookup endpoint."""
        with self.store.transaction() as db:
            row = self.store.load(db, request_id)
            require("callback" in row and time.time() < row["expires"])
            return row["callback_url"], row["callback"]

    def revoke(self, request_id: str, statement: str, chain: list[str]) -> None:
        with self.store.transaction() as db:
            row = self.store.load(db, request_id)
            require(row["status"] in {"pending", "approved", "issued"})
            decision = approval(
                statement, chain, row, self.config.owner_keys, self.config.issuer + "/approvals"
            )
            require(decision["decision"] == "deny")
            self.store.replay(db, "approval:" + decision["iss"], decision["jti"], decision["exp"])
            row["status"], row["revocation"] = "revoked", statement
            self.store.save(db, row)

    def contract(self, row: dict[str, Any], actual_details: Any) -> dict[str, Any]:
        return {
            "tenant": self.config.tenant,
            "connection": self.config.connection,
            "request_id": row["id"],
            "request_sha256": row["hash"],
            "actor": row["caller"],
            "channel": row["channel"],
            "callback_url": row["callback_url"],
            "audience": self.config.resource,
            "authorization_details": actual_details,
            "approval_sha256": commitment({"statement": row["approval"], "chain": row["chain"]}),
            "uses": 1,
            "response_policy": "calendar-event-id-and-receipt",
        }
