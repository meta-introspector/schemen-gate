from __future__ import annotations

import secrets
import sqlite3
import time

import pytest

from credential_broker.models import BrokerError, ProviderPolicy, Route
from credential_broker.vault import FileKeyProvider, Vault


def request(system, name="agent", connection="calendar", **fields):
    return system["client"].post(
        f"/v1/connections/{connection}/request",
        headers=system["headers"](name),
        json={"method": "GET", "path": "/ok", **fields},
    )


def test_real_http_write_and_secret_header_suppression(system):
    result = request(system, method="PATCH", path="/event", json={"start": "11:00"})
    assert result.status_code == 200 and result.json() == {"written": {"start": "11:00"}}
    assert system["state"]["writes"] == 1
    assert "set-cookie" not in result.headers and "x-upstream-secret" not in result.headers
    assert system["state"]["secret"] not in result.text
    assert result.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("name", ["other", "bob"])
def test_tenant_and_subject_binding(system, name):
    assert request(system, name).status_code == 404
    assert system["state"]["calls"] == []


def test_same_connection_id_isolated_between_tenants(system):
    assert system["provision"]("bobadmin", subjects=["other"]).status_code == 200
    assert request(system, "bob").status_code == 404
    assert request(system).status_code == 200


def test_authentication_and_no_secret_retrieval(system):
    client = system["client"]
    assert client.post("/v1/connections/calendar/request", json={}).status_code == 401
    assert (
        client.post(
            "/v1/connections/calendar/request", headers={"Authorization": "Bearer fake"}, json={}
        ).status_code
        == 401
    )
    assert client.get("/v1/connections/calendar", headers=system["headers"]()).status_code == 405
    assert system["provision"]("agent").status_code == 403
    assert client.delete("/v1/connections/calendar", headers=system["headers"]()).status_code == 403
    assert system["state"]["calls"] == []


@pytest.mark.parametrize(
    "fields",
    [
        {"method": "DELETE"},
        {"path": "/outside"},
        {"path": "https://evil.test/"},
        {"path": "//evil.test/"},
        {"path": "/../ok"},
        {"path": "/%2e%2e/ok"},
        {"path": "/ok?x=1"},
        {"path": "/ok\\evil"},
        {"headers": {"Authorization": "attacker"}},
        {"url": "https://evil.test"},
        {"tenant": "bob"},
        {"query": {"x": 12}},
    ],
)
def test_route_and_injection_attempts_never_dispatch(system, fields):
    assert request(system, **fields).status_code in {400, 403}
    assert system["state"]["calls"] == []


def test_rotation_and_revocation(system):
    assert request(system).status_code == 200
    old = system["state"]["secret"]
    system["state"]["secret"] = secrets.token_urlsafe(32)
    assert system["provision"]().status_code == 200
    assert request(system).status_code == 200
    assert system["state"]["calls"][-1]["auth"] != "Bearer " + old
    response = system["client"].delete(
        "/v1/connections/calendar", headers=system["headers"]("admin")
    )
    assert response.status_code == 204
    before = len(system["state"]["calls"])
    assert request(system).status_code == 404
    assert len(system["state"]["calls"]) == before


def test_expired_credential_is_not_used(system):
    assert system["provision"](expires_at=time.time() - 1).status_code == 200
    assert request(system).status_code == 403
    assert system["state"]["calls"] == []


@pytest.mark.parametrize(
    "path,code",
    [
        ("/redirect", "provider_redirect_blocked"),
        ("/echo", "provider_secret_echo_blocked"),
        ("/large", "provider_response_limit"),
    ],
)
def test_upstream_exfiltration_and_limits(system, path, code):
    result = request(system, path=path)
    assert result.status_code == 502 and result.json()["error"] == code
    assert len(system["state"]["calls"]) == 1
    assert system["state"]["secret"] not in result.text


def test_api_key_provider(system):
    assert system["provision"](connection="key", provider="apikey").status_code == 200
    assert request(system, connection="key").status_code == 200
    assert system["state"]["calls"][-1]["key"] == system["state"]["secret"]
    assert system["state"]["calls"][-1]["auth"] is None


def test_encryption_restart_audit_and_swapped_rows(system):
    vault = system["vault"]
    assert request(system).status_code == 200
    data = vault.path.read_bytes()
    assert system["state"]["secret"].encode() not in data
    assert system["tokens"]["agent"].encode() not in data
    restarted = Vault(vault.path, FileKeyProvider(system["key_path"]))
    assert restarted.get("alice", "calendar").secret == system["state"]["secret"]
    with sqlite3.connect(vault.path) as db:
        assert db.execute("SELECT event FROM audit WHERE event='request_finished'").fetchone()
        db.execute("UPDATE connections SET tenant='bob'")
    with pytest.raises(BrokerError, match="credential_unavailable"):
        restarted.get("bob", "calendar")


def test_tampered_ciphertext_and_wrong_key_fail_closed(system):
    vault = system["vault"]
    original = system["key_path"].read_bytes()
    system["key_path"].write_bytes(secrets.token_bytes(32))
    with pytest.raises(BrokerError, match="credential_unavailable"):
        Vault(vault.path, FileKeyProvider(system["key_path"]))
    system["key_path"].write_bytes(original)
    with sqlite3.connect(vault.path) as db:
        db.execute("UPDATE connections SET ciphertext=?", (b"tampered",))
    assert request(system).status_code == 503
    assert system["state"]["calls"] == []


def test_strict_json_and_request_limit(system):
    url = "/v1/connections/calendar/request"
    headers = {**system["headers"](), "Content-Type": "application/json"}
    for body, status in [
        (b'{"method":"GET","method":"DELETE"}', 400),
        (b'{"json":NaN}', 400),
        (b'{"json":1e999}', 400),
        (b"x" * 65537, 413),
    ]:
        assert system["client"].post(url, headers=headers, content=body).status_code == status
    assert system["state"]["calls"] == []


def test_customer_admin_cannot_add_unconfigured_provider(system):
    assert system["provision"](provider="https://evil.test").status_code == 400


def test_key_permissions(system):
    system["key_path"].chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        FileKeyProvider(system["key_path"]).key()


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.com",
        "https://" + "u:p" + "@example.com",
        "https://example.com/path",
        "https://example.com?x=1",
    ],
)
def test_provider_origin_validation(origin):
    with pytest.raises(ValueError):
        ProviderPolicy(origin, (Route("GET", "/ok"),))
