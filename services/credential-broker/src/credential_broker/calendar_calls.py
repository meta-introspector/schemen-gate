"""Exact one-off Calendar authority and ephemeral provider credential custody."""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.concurrency import run_in_threadpool

from . import call_gate
from .broker import Broker
from .calendar import GOOGLE_ORIGIN, calendar_request
from .call_ledger import CallLedger
from .call_receipt import public_key, sign_receipt
from .completion import settle
from .ephemeral import EphemeralSecrets
from .json_codec import strict_object
from .models import BrokerError, Principal, ProviderPolicy, Route, canonical, identifier

CALENDAR_PATH = "/calendar/v3/calendars/primary/events"


class CalendarCallService:
    def __init__(self, broker: Broker, *, policy: ProviderPolicy | None = None):
        self.broker = broker
        self.policy = policy or ProviderPolicy(GOOGLE_ORIGIN, (Route("POST", CALENDAR_PATH),))
        self.ledger = CallLedger(broker.vault)
        self.secrets = EphemeralSecrets()
        self.custody_owner = uuid.uuid4().hex
        root = broker.vault.keys.key()
        self.authority_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"schemen/calendar-authority-v1"
        ).derive(root)
        self.receipt_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"schemen/calendar-receipt-v1"
        ).derive(root)

    def approve(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        if not principal.admin:
            raise BrokerError(403, "admin_required")
        if set(data) != {"subject", "channel", "credential", "expires_in", "call"}:
            raise BrokerError(400, "invalid_call_fields")
        subject, channel = identifier(data["subject"]), identifier(data["channel"])
        ttl = data["expires_in"]
        if type(ttl) is not int or not 1 <= ttl <= 300:
            raise BrokerError(400, "invalid_call_expiry")
        request = calendar_request(data["call"])
        grant_id = uuid.uuid4().hex
        metadata: dict[str, Any] = {
            "schema": "schemen/calendar-one-off-v1",
            "grant_id": grant_id,
            "credential_generation": grant_id,
            "custody_owner": self.custody_owner,
            "tenant": principal.tenant,
            "subject": subject,
            "channel": channel,
            "result_channel": channel,
            "approved_by": principal.subject,
            "audience": self.ledger.audience,
            "expires_at": time.time() + ttl,
            "uses": 1,
            "provider_policy": self.policy.fingerprint(),
            "response_policy": "status-and-approved-event-id-v1",
        }
        contract = {**metadata, "request": request}
        aad = canonical(contract)
        aad_hash = hashlib.sha256(aad).hexdigest()
        gate = call_gate.issue(self.authority_key, contract, metadata["expires_at"])
        self.secrets.seal(grant_id, data["credential"], aad, metadata["expires_at"])
        try:
            self.ledger.add(metadata, aad_hash)
        except BaseException:
            self.secrets.discard(grant_id)
            raise
        return {
            "grant_id": grant_id,
            "gate": gate,
            "call": data["call"],
            "aad_sha256": aad_hash,
            "receipt_key": public_key(self.receipt_key),
        }

    async def execute(
        self, principal: Principal, grant_id: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        if set(data) != {"gate", "call"} or not isinstance(data["gate"], dict):
            raise BrokerError(400, "invalid_call_fields")
        policy = self.policy
        request = calendar_request(data["call"])
        metadata, aad_hash = await run_in_threadpool(self.ledger.lookup, grant_id, principal)
        if metadata["custody_owner"] != self.custody_owner:
            raise BrokerError(503, "call_owner_unavailable")
        contract = {
            **metadata,
            "tenant": principal.tenant,
            "subject": principal.subject,
            "channel": principal.channel,
            "result_channel": principal.channel,
            "audience": self.ledger.audience,
            "provider_policy": policy.fingerprint(),
            "request": request,
        }
        aad = canonical(contract)
        if hashlib.sha256(aad).hexdigest() != aad_hash:
            raise BrokerError(403, "call_contract_mismatch")
        call_gate.authenticate(self.authority_key, data["gate"], contract, metadata["expires_at"])
        # Commit the one-use boundary before making credential plaintext available.
        claim = asyncio.create_task(run_in_threadpool(self.ledger.consume, grant_id, aad_hash))
        claimed = False
        status: int | None = None
        outcome = "not_dispatched"
        try:
            await asyncio.shield(claim)
            claimed = True
            with self.secrets.take(grant_id, aad) as secret:
                outcome = "unknown"
                result = await self.broker.exchange(
                    policy,
                    secret,
                    request["method"],
                    request["path"],
                    request["query"],
                    request["json"],
                )
                status = result.status
                outcome = "provider_rejected"
                if 200 <= status < 300:
                    outcome = "invalid_provider_response"
                    try:
                        response = strict_object(result.body)
                        if (
                            status == 200
                            and isinstance(response, dict)
                            and response.get("id") == request["json"]["id"]
                            and response.get("status") == "confirmed"
                        ):
                            outcome = "confirmed"
                    except (ValueError, RecursionError):
                        pass
        except BrokerError:
            if not claimed:
                raise
            # Provider error text/body is not released; failure still burns the call.
            pass
        finally:
            interrupted = False
            # Even cancellation while the SQLite worker commits must wait for
            # its decision before cleaning custody. Never revive a consumed call.
            if not claimed:
                try:
                    _, interrupted = await settle(claim)
                    claimed = True
                except Exception:
                    pass
            if claimed:
                self.secrets.discard(grant_id)
                receipt = sign_receipt(
                    self.receipt_key,
                    {
                        "schema": "schemen/calendar-call-receipt-v1",
                        "grant_id": grant_id,
                        "aad_sha256": aad_hash,
                        "authority": "consumed",
                        "credential_custody": "destroyed",
                        "outcome": outcome,
                        "provider_status": status,
                        "event_id": request["json"]["id"],
                        "channel": principal.channel,
                    },
                )
                task = asyncio.create_task(run_in_threadpool(self.ledger.finish, grant_id, receipt))
                _, receipt_interrupted = await settle(task)
                interrupted = interrupted or receipt_interrupted
            if interrupted:
                raise asyncio.CancelledError
        # Never forward arbitrary provider content on the agent response channel.
        return {"event_id": request["json"]["id"], "provider_status": status, "receipt": receipt}

    def revoke(self, principal: Principal, grant_id: str) -> None:
        self.ledger.revoke(grant_id, principal, self.custody_owner)
        self.secrets.discard(grant_id)
