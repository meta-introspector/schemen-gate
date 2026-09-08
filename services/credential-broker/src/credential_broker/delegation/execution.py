"""Consume before dispatch; bridge the bound grant to existing Calendar credential custody."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Protocol

from credential_broker import call_gate
from credential_broker.calendar_calls import CalendarCallService
from credential_broker.models import Principal

from ._profile import Denied, details, require
from .crypto import check_dpop, valid, verify
from .service import ACCESS, Service


class NonceRequired(Denied):
    def __init__(self, nonce: str):
        super().__init__("use_dpop_nonce")
        self.nonce = nonce


@dataclass(frozen=True)
class Result:
    outcome: str
    event_id: str | None = None
    custody_receipt: dict[str, Any] | None = None


class Executor(Protocol):
    async def execute(
        self, request_id: str, actor: str, call: dict[str, Any], *, tenant: str, connection: str
    ) -> Result: ...


class CredentialSource(Protocol):
    def acquire(self) -> str:
        """Trusted account-specific source, invoked only after authorization consumption."""
        ...


class CalendarExecutor:
    def __init__(
        self,
        calendar: CalendarCallService,
        administrator: Principal,
        credentials: CredentialSource,
        connection: str,
    ):
        require(administrator.admin)
        self.calendar, self.administrator, self.credentials = calendar, administrator, credentials
        self.connection = connection

    async def execute(
        self, request_id: str, actor: str, call: dict[str, Any], *, tenant: str, connection: str
    ) -> Result:
        require(tenant == self.administrator.tenant and connection == self.connection)
        # Acquisition and sealing have no await/cancellation gap. The source owns its copies.
        credential = self.credentials.acquire()
        try:
            grant = self.calendar.approve(
                self.administrator,
                {
                    "subject": actor,
                    "channel": request_id,
                    "credential": credential,
                    "expires_in": 60,
                    "call": call,
                },
            )
        finally:
            del credential
        principal = Principal(self.administrator.tenant, actor, channel=request_id)
        try:
            output = await self.calendar.execute(
                principal, grant["grant_id"], {"gate": grant["gate"], "call": call}
            )
        finally:
            self.calendar.secrets.discard(grant["grant_id"])
        return Result(output["receipt"]["body"]["outcome"], output["event_id"], output["receipt"])


async def execute(
    service: Service, executor: Executor, token: str, proof: str, call: dict[str, Any]
) -> dict[str, Any]:
    claims, _ = verify(token, ACCESS, expected=service.signing_key)
    valid(claims, service.config.issuer, service.config.resource, maximum=60)
    with service.store.transaction() as db:
        row = service.store.load(db, claims.get("request_id"))
        require(
            row["status"] == "issued"
            and row["access_token"] == token
            and time.time() < row["expires"]
        )
        require(claims.get("cnf") == {"jkt": row["caller"]})
        try:
            jti, expires = check_dpop(
                proof, service.config.resource, row["execution_nonce"], row["caller"], token
            )
        except Denied as exc:
            if exc.code == "use_dpop_nonce":
                raise NonceRequired(row["execution_nonce"]) from None
            raise
        actual = details([{**row["details"][0], "call": call}], resource=service.config.resource)
        call_gate.authenticate(
            service.gate_key,
            claims["urn:schemen:gate"],
            service.contract(row, actual),
            claims["exp"],
        )
        require(actual == row["details"])
        service.store.replay(db, "dpop:" + row["caller"], jti, expires)
        row["status"] = "consumed"
        service.store.save(db, row)
    # The committed action budget never reopens, including on crash or cancellation.
    result = Result("unknown")
    try:
        result = await executor.execute(
            row["id"],
            row["caller"],
            call,
            tenant=service.config.tenant,
            connection=service.config.connection,
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        pass  # Never expose provider/credential-source exception text.
    finally:
        receipt = service.signed(
            "schemen-result+jwt",
            row["caller"],
            int(time.time()) + 300,
            {
                "request_id": row["id"],
                "request_sha256": row["hash"],
                "authority": "consumed",
                "outcome": result.outcome,
                "event_id": result.event_id,
                "custody_receipt": result.custody_receipt,
            },
        )
        with service.store.transaction() as db:
            stored = service.store.load(db, row["id"])
            stored["result"] = receipt
            service.store.save(db, stored)
    return {"receipt": receipt}
