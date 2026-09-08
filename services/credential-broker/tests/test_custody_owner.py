"""Custody claims must come from the instance that owns the pending credential."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest
from test_calendar_calls import (
    EVENT_ID,
    approve,
    checked_receipt,
    execute,
)
from test_calendar_calls import (
    calendar_system as calendar_system,
)

from credential_broker.broker import BrokerResponse
from credential_broker.calendar_calls import CALENDAR_PATH, CalendarCallService
from credential_broker.models import ProviderPolicy, Route


@pytest.mark.parametrize("operation", ["execute", "revoke"])
def test_wrong_live_owner_cannot_consume_revoke_or_attest_destruction(calendar_system, operation):
    system = calendar_system
    owner = system["calendar_service"]
    grant = approve(system)
    key = owner.secrets._entries[grant["grant_id"]].key
    stranger = CalendarCallService(system["broker"], policy=owner.policy)
    system["app"].state.calendar_calls = stranger
    try:
        if operation == "execute":
            response = execute(system, grant)
        else:
            response = system["client"].delete(
                f"/v1/calendar-calls/{grant['grant_id']}", headers=system["headers"]("admin")
            )
        assert response.status_code == 503, response.text
        assert response.json() == {"error": "call_owner_unavailable"}
        assert owner.secrets.active_count == 1 and any(key)
        assert stranger.secrets.active_count == 0
        assert system["state"]["calls"] == []
        with sqlite3.connect(system["vault"].path) as db:
            assert db.execute(
                "SELECT state,receipt FROM calendar_calls WHERE id=?", (grant["grant_id"],)
            ).fetchone() == ("pending", None)
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM audit WHERE connection=? AND event IN "
                    "('call_consumed_before_dispatch','call_revoked','call_credential_destroyed')",
                    (grant["grant_id"],),
                ).fetchone()[0]
                == 0
            )
        receipt = system["client"].get(
            f"/v1/calendar-calls/{grant['grant_id']}/receipt", headers=system["headers"]()
        )
        assert receipt.status_code == 409
        assert receipt.json() == {"error": "receipt_unavailable"}
    finally:
        system["app"].state.calendar_calls = owner
        stranger.secrets.close()
    # Wrong routing cannot burn the real owner's correctly authorized operation.
    accepted = execute(system, grant)
    assert accepted.status_code == 200
    assert checked_receipt(system, grant, accepted.json())["outcome"] == "confirmed"
    assert key == bytearray(32)
    assert owner.secrets.active_count == 0
    assert len(system["state"]["calls"]) == 1


def test_new_instance_can_retrieve_existing_signed_receipt_without_custody(calendar_system):
    system = calendar_system
    owner = system["calendar_service"]
    grant = approve(system)
    completed = execute(system, grant)
    assert completed.status_code == 200
    expected = completed.json()["receipt"]
    restarted = CalendarCallService(system["broker"], policy=owner.policy)
    system["app"].state.calendar_calls = restarted
    try:
        response = system["client"].get(
            f"/v1/calendar-calls/{grant['grant_id']}/receipt", headers=system["headers"]()
        )
        assert response.status_code == 200
        assert response.json() == expected
        assert (
            checked_receipt(system, grant, {"receipt": response.json()})["outcome"] == "confirmed"
        )
        assert restarted.secrets.active_count == 0
        assert len(system["state"]["calls"]) == 1
    finally:
        system["app"].state.calendar_calls = owner
        restarted.secrets.close()


def test_dispatch_uses_the_policy_snapshot_authenticated_before_consume(
    calendar_system, monkeypatch
):
    system = calendar_system
    service = system["calendar_service"]
    approved_policy = service.policy
    grant = approve(system)
    changed_policy = ProviderPolicy("https://unapproved.example", (Route("POST", CALENDAR_PATH),))
    consume = service.ledger.consume
    dispatched: list[ProviderPolicy] = []

    def reconfigure_after_commit(grant_id: str, aad_hash: str) -> None:
        consume(grant_id, aad_hash)
        service.policy = changed_policy

    async def observe_exchange(
        policy: ProviderPolicy,
        secret: str,
        method: str,
        path: str,
        query: dict[str, str],
        body: Any,
    ) -> BrokerResponse:
        dispatched.append(policy)
        assert service.policy is changed_policy
        assert secret == system["state"]["secret"]
        assert method == "POST" and path == CALENDAR_PATH
        assert query == {"sendUpdates": "none"}
        assert body == grant["call"]["event"]
        return BrokerResponse(
            200, json.dumps({"id": EVENT_ID, "status": "confirmed"}).encode(), "application/json"
        )

    monkeypatch.setattr(service.ledger, "consume", reconfigure_after_commit)
    monkeypatch.setattr(service.broker, "exchange", observe_exchange)
    result = execute(system, grant)
    assert result.status_code == 200
    assert dispatched == [approved_policy]
    assert dispatched[0] is approved_policy
    assert checked_receipt(system, grant, result.json())["outcome"] == "confirmed"
    assert service.secrets.active_count == 0
    # The stand-in observes dispatch arguments without contacting either origin.
    assert system["state"]["calls"] == []
