"""Exercise the one-call boundary through independent HTTP broker/provider sockets."""

from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from typing import Any

import pytest

from credential_broker.calendar_calls import CALENDAR_PATH, CalendarCallService
from credential_broker.call_receipt import public_key, verify_receipt
from credential_broker.models import BrokerError, ProviderPolicy, Route

EVENT_ID = "ec8a63348cd24a2ba3eb25a7484179f1"
PRIVATE_TITLE = "Private calendar title canary 8fb936"
PRIVATE_DESCRIPTION = "Private calendar description canary 4cd214"


def proposal() -> dict[str, Any]:
    return {
        "calendar_id": "primary",
        "send_updates": "none",
        "event": {
            "id": EVENT_ID,
            "summary": PRIVATE_TITLE,
            "description": PRIVATE_DESCRIPTION,
            "start": {"dateTime": "2026-09-09T17:00:00Z"},
            "end": {"dateTime": "2026-09-09T17:30:00Z"},
        },
    }


@pytest.fixture
def calendar_system(system: dict[str, Any]) -> dict[str, Any]:
    # The one-off credential must not also exist in a reusable legacy connection.
    system["vault"].delete("alice", "calendar")
    policy = ProviderPolicy(
        system["providers"]["fixture"].origin,
        (Route("POST", CALENDAR_PATH),),
        allow_loopback_http=True,
    )
    service = CalendarCallService(system["broker"], policy=policy)
    system["app"].state.calendar_calls = service
    system["calendar_service"] = service
    # Pin independently of the key advertised in an approval response.
    system["pinned_receipt_key"] = public_key(service.receipt_key)
    return system


def approve(system: dict[str, Any], **changes: Any) -> dict[str, Any]:
    data = {
        "subject": "agent",
        "channel": "default",
        "credential": system["state"]["secret"],
        "expires_in": 300,
        "call": proposal(),
        **changes,
    }
    response = system["client"].post(
        "/v1/calendar-calls", headers=system["headers"]("admin"), json=data
    )
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["receipt_key"] == system["pinned_receipt_key"]
    assert data["credential"] not in response.text
    return result


def execute(system: dict[str, Any], grant: dict[str, Any], *, name: str = "agent", **changes: Any):
    return system["client"].post(
        f"/v1/calendar-calls/{grant['grant_id']}/execute",
        headers=system["headers"](name),
        json={"gate": grant["gate"], "call": grant["call"], **changes},
    )


def checked_receipt(system: dict[str, Any], grant: dict[str, Any], result: dict[str, Any]):
    return verify_receipt(
        result["receipt"],
        system["pinned_receipt_key"],
        grant["grant_id"],
        grant["aad_sha256"],
    )


def test_calendar_exact_http_call_and_no_reusable_connection(calendar_system):
    system = calendar_system
    grant = approve(system)
    owned_key = system["calendar_service"].secrets._entries[grant["grant_id"]].key
    assert any(owned_key)
    for connection in ("calendar", grant["grant_id"]):
        raw = system["client"].post(
            f"/v1/connections/{connection}/request",
            headers=system["headers"](),
            json={"method": "POST", "path": CALENDAR_PATH, "json": grant["call"]["event"]},
        )
        assert raw.status_code == 404
    assert system["state"]["calls"] == []
    response = execute(system, grant)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["event_id"] == EVENT_ID
    assert result["provider_status"] == 200
    assert checked_receipt(system, grant, result)["outcome"] == "confirmed"
    assert len(system["state"]["calls"]) == 1
    wire = system["state"]["calls"][0]
    assert wire["method"] == "POST"
    assert wire["path"] == CALENDAR_PATH + "?sendUpdates=none"
    assert json.loads(wire["body"]) == grant["call"]["event"]
    assert wire["auth"] == "Bearer " + system["state"]["secret"]
    assert wire["key"] is None
    assert "set-cookie" not in response.headers
    assert "x-upstream-secret" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert system["state"]["secret"] not in response.text
    assert PRIVATE_TITLE not in response.text and PRIVATE_DESCRIPTION not in response.text
    assert system["calendar_service"].secrets.active_count == 0
    assert bytes(owned_key) == b"\x00" * 32
    assert execute(system, grant).status_code == 409
    assert len(system["state"]["calls"]) == 1


def test_calendar_issuance_requires_trusted_admin_and_configured_principal(calendar_system):
    system = calendar_system
    data = {
        "subject": "agent",
        "channel": "default",
        "credential": system["state"]["secret"],
        "expires_in": 300,
        "call": proposal(),
    }
    for headers, status in (({}, 401), (system["headers"](), 403)):
        response = system["client"].post("/v1/calendar-calls", headers=headers, json=data)
        assert response.status_code == status
        assert data["credential"] not in response.text
    for changes in ({"subject": "unknown-agent"}, {"channel": "unknown-channel"}):
        response = system["client"].post(
            "/v1/calendar-calls", headers=system["headers"]("admin"), json={**data, **changes}
        )
        assert response.status_code == 400
        assert data["credential"] not in response.text
    assert system["state"]["calls"] == []
    assert system["calendar_service"].secrets.active_count == 0


@pytest.mark.parametrize("name", ["other", "bob", "otherchannel"])
def test_calendar_identity_and_channel_substitution_never_dispatch(calendar_system, name):
    system = calendar_system
    grant = approve(system)
    assert execute(system, grant, name=name).status_code == 404
    assert system["state"]["calls"] == []
    # A rejected identity cannot consume the intended caller's authorization.
    assert execute(system, grant).status_code == 200
    assert len(system["state"]["calls"]) == 1


@pytest.mark.parametrize("field", ["id", "summary", "description", "start", "end"])
def test_calendar_changed_approved_argument_never_dispatches(calendar_system, field):
    system = calendar_system
    grant = approve(system)
    changed = deepcopy(grant["call"])
    replacements = {
        "id": "a" * 32,
        "summary": "Changed meeting",
        "description": "Changed agenda",
        "start": {"dateTime": "2026-09-09T17:01:00Z"},
        "end": {"dateTime": "2026-09-09T17:31:00Z"},
    }
    changed["event"][field] = replacements[field]
    response = execute(system, grant, call=changed)
    assert response.status_code == 403
    assert response.json() == {"error": "call_contract_mismatch"}
    assert system["state"]["calls"] == []
    assert execute(system, grant).status_code == 200


def test_calendar_gate_tampering_and_cross_grant_substitution_fail_closed(calendar_system):
    system = calendar_system
    first, second = approve(system), approve(system)
    altered = deepcopy(first["gate"])
    ciphertext = bytearray.fromhex(altered["ciphertext"])
    ciphertext[-1] ^= 1
    altered["ciphertext"] = ciphertext.hex()
    assert execute(system, first, gate=altered).status_code == 403
    assert execute(system, second, gate=first["gate"]).status_code == 403
    assert system["state"]["calls"] == []
    assert execute(system, first).status_code == 200


def test_calendar_provider_policy_drift_invalidates_existing_approval(calendar_system):
    system = calendar_system
    service = system["calendar_service"]
    grant = approve(system)
    policy = service.policy
    service.policy = ProviderPolicy(
        policy.origin, (*policy.routes, Route("GET", "/other")), allow_loopback_http=True
    )
    assert execute(system, grant).status_code == 403
    assert system["state"]["calls"] == []
    service.policy = policy
    assert execute(system, grant).status_code == 200


def test_calendar_concurrent_replays_dispatch_once(calendar_system):
    system = calendar_system
    grant = approve(system)
    with ThreadPoolExecutor(max_workers=2) as workers:
        responses = list(workers.map(lambda _: execute(system, grant), range(2)))
    assert sorted(response.status_code for response in responses) == [200, 409]
    assert len(system["state"]["calls"]) == 1
    success = next(response.json() for response in responses if response.status_code == 200)
    assert checked_receipt(system, grant, success)["outcome"] == "confirmed"
    assert system["calendar_service"].secrets.active_count == 0


def test_calendar_receipt_verifies_only_for_pinned_key_and_exact_grant(calendar_system):
    system = calendar_system
    issuer = system["client"].get("/v1/calendar-calls/issuer", headers=system["headers"]())
    assert issuer.status_code == 200
    assert issuer.json()["receipt_key"] == system["pinned_receipt_key"]
    assert system["client"].get("/v1/calendar-calls/issuer").status_code == 401
    grant = approve(system)
    response = execute(system, grant)
    assert response.status_code == 200
    receipt = response.json()["receipt"]
    path = f"/v1/calendar-calls/{grant['grant_id']}/receipt"
    stored = system["client"].get(path, headers=system["headers"]())
    assert stored.status_code == 200
    assert stored.json() == receipt
    for name in ("other", "bob", "otherchannel"):
        assert system["client"].get(path, headers=system["headers"](name)).status_code == 404
    good = checked_receipt(system, grant, response.json())
    assert good["authority"] == "consumed"
    assert good["credential_custody"] == "destroyed"
    altered = deepcopy(receipt)
    altered["body"]["provider_status"] = 401
    variants = [
        (altered, system["pinned_receipt_key"], grant["grant_id"], grant["aad_sha256"]),
        (receipt, "00" * 32, grant["grant_id"], grant["aad_sha256"]),
        (receipt, system["pinned_receipt_key"], "another-grant", grant["aad_sha256"]),
        (receipt, system["pinned_receipt_key"], grant["grant_id"], "00" * 32),
    ]
    for variant in variants:
        with pytest.raises(BrokerError) as error:
            verify_receipt(*variant)
        assert (error.value.status, error.value.code) == (403, "invalid_call_receipt")


def test_calendar_ledger_and_observer_logs_do_not_retain_credential_or_event_text(
    calendar_system, caplog, capsys
):
    system = calendar_system
    grant = approve(system)
    response = execute(system, grant)
    assert response.status_code == 200
    with sqlite3.connect(system["vault"].path) as database:
        persisted = "\n".join(database.iterdump())
        assert database.execute("SELECT COUNT(*) FROM connections").fetchone()[0] == 0
        assert (
            database.execute(
                "SELECT state FROM calendar_calls WHERE id=?", (grant["grant_id"],)
            ).fetchone()[0]
            == "consumed"
        )
    observed = capsys.readouterr()
    for value in (system["state"]["secret"], PRIVATE_TITLE, PRIVATE_DESCRIPTION):
        assert value not in persisted
        assert value.encode() not in system["vault"].path.read_bytes()
        assert value not in caplog.text
        assert value not in observed.out + observed.err
        assert value not in response.text
    assert system["calendar_service"].secrets.active_count == 0


def test_calendar_restart_loses_pending_key_and_fails_closed(calendar_system):
    system = calendar_system
    original = system["calendar_service"]
    grant = approve(system)
    original.secrets.close()
    restarted = CalendarCallService(system["broker"], policy=original.policy)
    system["app"].state.calendar_calls = restarted
    response = execute(system, grant)
    assert response.status_code == 503
    assert response.json() == {"error": "call_owner_unavailable"}
    assert system["state"]["calls"] == []
    assert execute(system, grant).status_code == 503
    path = f"/v1/calendar-calls/{grant['grant_id']}/receipt"
    assert system["client"].get(path, headers=system["headers"]()).status_code == 409


def test_calendar_ledger_rollback_cannot_restore_consumed_ram_key(calendar_system):
    system = calendar_system
    grant = approve(system)
    with sqlite3.connect(system["vault"].path) as database:
        pending = database.execute(
            "SELECT * FROM calendar_calls WHERE id=?", (grant["grant_id"],)
        ).fetchone()
    assert execute(system, grant).status_code == 200
    with sqlite3.connect(system["vault"].path) as database:
        database.execute("DELETE FROM calendar_calls WHERE id=?", (grant["grant_id"],))
        placeholders = ",".join("?" for _ in pending)
        database.execute(f"INSERT INTO calendar_calls VALUES ({placeholders})", pending)
    response = execute(system, grant)
    assert response.status_code == 200
    assert checked_receipt(system, grant, response.json())["outcome"] == "not_dispatched"
    assert len(system["state"]["calls"]) == 1
    assert system["calendar_service"].secrets.active_count == 0


def test_calendar_secret_variation_preserves_declared_agent_output_projection(calendar_system):
    system = calendar_system
    secrets = ["synthetic-provider-secret-alpha-3849", "synthetic-provider-secret-bravo-8172"]
    projections = []
    responses = []
    for secret in secrets:
        system["state"]["secret"] = secret
        grant = approve(system)
        response = execute(system, grant)
        assert response.status_code == 200
        result = response.json()
        receipt = checked_receipt(system, grant, result)
        projections.append(
            {
                "event_id": result["event_id"],
                "provider_status": result["provider_status"],
                "authority": receipt["authority"],
                "credential_custody": receipt["credential_custody"],
                "outcome": receipt["outcome"],
                "receipt_provider_status": receipt["provider_status"],
            }
        )
        responses.append(response.text + json.dumps(dict(response.headers)))
    assert projections[0] == projections[1]
    assert projections[0]["outcome"] == "confirmed"
    first, second = system["state"]["calls"]
    assert first["body"] == second["body"]
    assert first["path"] == second["path"]
    assert first["auth"] != second["auth"]
    for secret in secrets:
        assert all(secret not in response for response in responses)
