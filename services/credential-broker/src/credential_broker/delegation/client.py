"""Pinned service verification and durable, idempotent callback receipt on the caller."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, cast

from joserfc.jwk import OKPKey

from ._profile import require
from .crypto import commitment, valid, verify
from .service import CALLBACK, PENDING, REQUEST
from .store import Store


class Inbox:
    def __init__(
        self,
        issuer: str,
        service_key: OKPKey,
        caller: OKPKey,
        callback_url: str,
        database: Path,
        encryption_key: bytes,
    ):
        self.issuer, self.service_key, self.caller, self.url = (
            issuer,
            service_key,
            caller,
            callback_url,
        )
        self.store = Store(
            database,
            commitment([issuer, service_key.thumbprint(), caller.thumbprint(), callback_url]),
            encryption_key,
        )

    def expect(self, request: str, pending: str) -> str:
        proposed, _ = verify(request, REQUEST, expected=self.caller)
        valid(proposed, self.caller.thumbprint(), self.issuer + "/requests")
        ack, _ = verify(pending, PENDING, expected=self.service_key)
        valid(ack, self.issuer, self.caller.thumbprint())
        require(
            ack["request_sha256"] == commitment(proposed)
            and ack["caller_nonce"] == proposed["nonce"]
            and ack["exp"] <= proposed["exp"]
        )
        with self.store.transaction() as db:
            self.store.add(
                db,
                {
                    "id": ack["request_id"],
                    "hash": ack["request_sha256"],
                    "nonce": proposed["nonce"],
                    "expires": ack["exp"],
                    "resource": proposed["resource"],
                    "event_id": proposed["authorization_details"][0]["call"]["event"]["id"],
                },
            )
        return cast(str, ack["request_id"])

    def receive(self, statement: str) -> None:
        claims, _ = verify(statement, CALLBACK, expected=self.service_key)
        valid(claims, self.issuer, self.url)
        require(claims.get("cnf") == {"jkt": self.caller.thumbprint()})
        with self.store.transaction() as db:
            row = self.store.load(db, claims.get("request_id"))
            require(
                time.time() < row["expires"]
                and claims["request_sha256"] == row["hash"]
                and claims["caller_nonce"] == row["nonce"]
                and claims["resource"] == row["resource"]
                and claims["exp"] <= row["expires"]
            )
            require(claims["decision"] in {"approve", "deny"})
            if "callback" in row:
                require(row["callback"] == statement, "callback_conflict")
                return  # Authenticated retries acknowledge the same message without a second decision.
            self.store.replay(db, "callback", claims["jti"], claims["exp"])
            row["callback"] = statement
            self.store.save(db, row)

    def result(self, statement: str, request_id: str) -> dict[str, Any]:
        claims, _ = verify(statement, "schemen-result+jwt", expected=self.service_key)
        valid(claims, self.issuer, self.caller.thumbprint())
        with self.store.transaction() as db:
            row = self.store.load(db, request_id)
            require(claims["request_id"] == request_id and claims["request_sha256"] == row["hash"])
            require(
                claims.get("authority") == "consumed"
                and claims.get("event_id") in {None, row["event_id"]}
            )
            if claims.get("outcome") == "confirmed":
                require(claims.get("event_id") == row["event_id"])
        return claims
