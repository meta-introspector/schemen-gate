"""Fault injection at custody, durable authority, dispatch, and response boundaries."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from test_calendar_calls import (  # noqa: F401 -- exposes the shared fixture to pytest
    EVENT_ID,
    PRIVATE_DESCRIPTION,
    approve,
    checked_receipt,
    execute,
    proposal,
)
from test_calendar_calls import calendar_system as calendar_system

import credential_broker.broker as broker_module
from credential_broker.models import Principal


def ledger_row(system: dict[str, Any], grant: dict[str, Any]) -> tuple[str, str | None]:
    with sqlite3.connect(system["vault"].path) as database:
        return database.execute(
            "SELECT state,receipt FROM calendar_calls WHERE id=?", (grant["grant_id"],)
        ).fetchone()


def fault_on_audit(system: dict[str, Any], event: str) -> None:
    # The event is a test-owned constant. Trigger the failure after the authority
    # update or receipt update, so transaction rollback is exercised for real.
    assert event in {"call_consumed_before_dispatch", "call_credential_destroyed"}
    with sqlite3.connect(system["vault"].path) as database:
        database.execute(
            "CREATE TRIGGER injected_audit_failure BEFORE INSERT ON audit "
            f"WHEN NEW.event='{event}' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END"
        )


@pytest.mark.parametrize("failure", ["audit", "commit"])
def test_failed_authority_transaction_never_releases_credential_or_dispatches(
    calendar_system, monkeypatch, failure
):
    system = calendar_system
    service = system["calendar_service"]
    grant = approve(system)
    key = service.secrets._entries[grant["grant_id"]].key
    if failure == "audit":
        fault_on_audit(system, "call_consumed_before_dispatch")
    else:
        original_db = system["vault"]._db

        @contextmanager
        def commit_failure(*, verify: bool = True) -> Iterator[sqlite3.Connection]:
            with original_db(verify=verify) as database:
                yield database
                consumed = database.execute(
                    "SELECT state FROM calendar_calls WHERE id=?", (grant["grant_id"],)
                ).fetchone()
                if consumed is not None and consumed[0] == "consumed":
                    database.set_authorizer(
                        lambda action, arg, *_: (
                            sqlite3.SQLITE_DENY
                            if action == sqlite3.SQLITE_TRANSACTION and arg == "COMMIT"
                            else sqlite3.SQLITE_OK
                        )
                    )

        monkeypatch.setattr(system["vault"], "_db", commit_failure)

    response = execute(system, grant)
    assert response.status_code == 500
    assert system["state"]["secret"] not in response.text
    assert system["state"]["calls"] == []
    assert ledger_row(system, grant) == ("pending", None)
    assert service.secrets.active_count == 1
    assert any(key)
    with sqlite3.connect(system["vault"].path) as database:
        assert (
            database.execute(
                "SELECT COUNT(*) FROM audit WHERE connection=? AND event='call_consumed_before_dispatch'",
                (grant["grant_id"],),
            ).fetchone()[0]
            == 0
        )
        if failure == "audit":
            database.execute("DROP TRIGGER injected_audit_failure")
    if failure == "commit":
        monkeypatch.setattr(system["vault"], "_db", original_db)
    # A transaction that never committed does not silently consume authority.
    assert execute(system, grant).status_code == 200
    assert len(system["state"]["calls"]) == 1
    assert key == bytearray(32)


def test_receipt_transaction_failure_burns_authority_and_never_replays(calendar_system):
    system = calendar_system
    service = system["calendar_service"]
    grant = approve(system)
    key = service.secrets._entries[grant["grant_id"]].key
    fault_on_audit(system, "call_credential_destroyed")
    response = execute(system, grant)
    assert response.status_code == 500
    assert system["state"]["writes"] == 1
    assert ledger_row(system, grant) == ("consumed", None)
    assert service.secrets.active_count == 0
    assert key == bytearray(32)
    assert execute(system, grant).status_code == 409
    assert system["state"]["writes"] == 1
    receipt = system["client"].get(
        f"/v1/calendar-calls/{grant['grant_id']}/receipt", headers=system["headers"]()
    )
    assert receipt.status_code == 409
    assert receipt.json() == {"error": "receipt_unavailable"}


def test_timeout_after_provider_write_is_unknown_and_cannot_retry(calendar_system, monkeypatch):
    system = calendar_system
    grant = approve(system)
    key = system["calendar_service"].secrets._entries[grant["grant_id"]].key
    system["state"]["drip_body"] = 0.02
    monkeypatch.setattr(broker_module, "PROVIDER_TIMEOUT", 0.15)
    response = execute(system, grant)
    assert response.status_code == 200
    result = response.json()
    assert system["state"]["writes"] == 1
    assert result["provider_status"] is None
    assert checked_receipt(system, grant, result)["outcome"] == "unknown"
    assert result["event_id"] == EVENT_ID
    assert system["calendar_service"].secrets.active_count == 0
    assert key == bytearray(32)
    assert execute(system, grant).status_code == 409
    assert len(system["state"]["calls"]) == 1
    assert system["state"]["writes"] == 1


@pytest.mark.parametrize(
    "status,body",
    [
        (200, b"invalid-json"),
        (200, json.dumps({"id": EVENT_ID}).encode()),
        (200, json.dumps({"id": EVENT_ID, "status": "cancelled"}).encode()),
        (200, ('{"id":"wrong","id":"' + EVENT_ID + '","status":"confirmed"}').encode()),
        (200, b'{"id":"different-event"}'),
        (200, b"[]"),
        (200, b"null"),
        (201, json.dumps({"id": EVENT_ID}).encode()),
        (202, json.dumps({"id": EVENT_ID}).encode()),
        (204, b""),
    ],
)
def test_provider_success_must_match_calendar_response_contract(calendar_system, status, body):
    system = calendar_system
    system["state"]["calendar_status"] = status
    system["state"]["calendar_response"] = body
    grant = approve(system)
    response = execute(system, grant)
    assert response.status_code == 200
    result = response.json()
    assert result["provider_status"] == status
    assert checked_receipt(system, grant, result)["outcome"] == "invalid_provider_response"
    assert result["event_id"] == EVENT_ID
    assert system["calendar_service"].secrets.active_count == 0
    assert execute(system, grant).status_code == 409
    assert len(system["state"]["calls"]) == 1


@pytest.mark.parametrize("status", [400, 401, 403, 429])
def test_provider_rejection_never_passes_its_body_or_headers(calendar_system, status):
    system = calendar_system
    system["state"]["calendar_status"] = status
    system["state"]["calendar_response"] = json.dumps({"error": PRIVATE_DESCRIPTION}).encode()
    grant = approve(system)
    response = execute(system, grant)
    assert response.status_code == 200
    result = response.json()
    assert result["provider_status"] == status
    assert checked_receipt(system, grant, result)["outcome"] == "provider_rejected"
    assert PRIVATE_DESCRIPTION not in response.text
    assert system["state"]["secret"] not in response.text
    assert "set-cookie" not in response.headers
    assert "x-upstream-secret" not in response.headers
    assert execute(system, grant).status_code == 409
    assert len(system["state"]["calls"]) == 1


def test_idle_expiry_destroys_pending_key_without_a_followup_request(calendar_system):
    system = calendar_system
    grant = approve(system, expires_in=1)
    service = system["calendar_service"]
    key = service.secrets._entries[grant["grant_id"]].key
    deadline = time.monotonic() + 3
    # Do not call active_count/prune: only the app's idle lifecycle may erase it.
    while any(key) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert key == bytearray(32)
    assert grant["grant_id"] not in service.secrets._entries
    assert execute(system, grant).status_code == 403
    assert system["state"]["calls"] == []


def test_revoke_destroys_pending_key_and_denies_replay(calendar_system):
    system = calendar_system
    grant = approve(system)
    service = system["calendar_service"]
    key = service.secrets._entries[grant["grant_id"]].key
    response = system["client"].delete(
        f"/v1/calendar-calls/{grant['grant_id']}", headers=system["headers"]("admin")
    )
    assert response.status_code == 204
    assert ledger_row(system, grant) == ("revoked", None)
    assert service.secrets.active_count == 0
    assert key == bytearray(32)
    assert execute(system, grant).status_code == 409
    assert system["state"]["calls"] == []


@pytest.mark.parametrize("cancellations", [1, 2])
def test_cancellation_after_consume_commit_waits_for_worker_then_destroys_custody(
    calendar_system, monkeypatch, cancellations
):
    system = calendar_system
    service = system["calendar_service"]
    grant = approve(system)
    key = service.secrets._entries[grant["grant_id"]].key
    committed, release = threading.Event(), threading.Event()
    original_consume = service.ledger.consume

    def delayed_return(grant_id: str, aad_hash: str) -> None:
        original_consume(grant_id, aad_hash)
        committed.set()
        assert release.wait(timeout=5), "test failed to release SQLite worker"

    monkeypatch.setattr(service.ledger, "consume", delayed_return)

    async def scenario() -> None:
        task = asyncio.create_task(
            service.execute(
                Principal("alice", "agent"),
                grant["grant_id"],
                {"gate": grant["gate"], "call": proposal()},
            )
        )
        try:
            assert await asyncio.to_thread(committed.wait, 3)
            assert ledger_row(system, grant) == ("consumed", None)
            for _ in range(cancellations):
                task.cancel()
                await asyncio.sleep(0)
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)

    asyncio.run(scenario())
    assert service.secrets.active_count == 0
    assert key == bytearray(32)
    assert system["state"]["calls"] == []
    receipt = service.ledger.receipt(grant["grant_id"], Principal("alice", "agent"))
    assert checked_receipt(system, grant, {"receipt": receipt})["outcome"] == "not_dispatched"
    assert execute(system, grant).status_code == 409


@pytest.mark.parametrize("after_write", [False, True])
def test_cancellation_during_exchange_destroys_key_and_records_unknown(
    calendar_system, monkeypatch, after_write
):
    system = calendar_system
    service = system["calendar_service"]
    grant = approve(system)
    key = service.secrets._entries[grant["grant_id"]].key
    original_exchange = service.broker.exchange

    async def scenario() -> None:
        entered = asyncio.Event()

        async def suspended_exchange(*args, **kwargs):
            if after_write:
                await original_exchange(*args, **kwargs)
            entered.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(service.broker, "exchange", suspended_exchange)
        task = asyncio.create_task(
            service.execute(
                Principal("alice", "agent"),
                grant["grant_id"],
                {"gate": grant["gate"], "call": proposal()},
            )
        )
        await asyncio.wait_for(entered.wait(), timeout=3)
        assert key == bytearray(32)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)

    asyncio.run(scenario())
    assert service.secrets.active_count == 0
    assert key == bytearray(32)
    assert system["state"]["writes"] == int(after_write)
    receipt = service.ledger.receipt(grant["grant_id"], Principal("alice", "agent"))
    assert checked_receipt(system, grant, {"receipt": receipt})["outcome"] == "unknown"
    assert receipt["body"]["provider_status"] is None
    assert execute(system, grant).status_code == 409
    assert len(system["state"]["calls"]) == int(after_write)


@pytest.mark.parametrize("cancellations", [1, 2])
def test_cancellation_during_receipt_commit_waits_for_signed_disposition(
    calendar_system, monkeypatch, cancellations
):
    system = calendar_system
    service = system["calendar_service"]
    grant = approve(system)
    key = service.secrets._entries[grant["grant_id"]].key
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original_finish = service.ledger.finish

    def delayed_finish(grant_id: str, receipt: dict[str, Any]) -> None:
        entered.set()
        assert release.wait(timeout=5), "test failed to release receipt worker"
        original_finish(grant_id, receipt)
        finished.set()

    monkeypatch.setattr(service.ledger, "finish", delayed_finish)

    async def scenario() -> None:
        task = asyncio.create_task(
            service.execute(
                Principal("alice", "agent"),
                grant["grant_id"],
                {"gate": grant["gate"], "call": proposal()},
            )
        )
        try:
            assert await asyncio.to_thread(entered.wait, 3)
            assert key == bytearray(32)
            for _ in range(cancellations):
                task.cancel()
                await asyncio.sleep(0)
                await asyncio.sleep(0)
            assert not task.done(), "cancellation detached the mandatory receipt transaction"
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        assert finished.is_set()

    asyncio.run(scenario())
    assert service.secrets.active_count == 0
    assert key == bytearray(32)
    assert system["state"]["writes"] == 1
    receipt = service.ledger.receipt(grant["grant_id"], Principal("alice", "agent"))
    assert checked_receipt(system, grant, {"receipt": receipt})["outcome"] == "confirmed"
    assert execute(system, grant).status_code == 409
    assert len(system["state"]["calls"]) == 1
