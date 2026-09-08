from __future__ import annotations

import json
import os
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from test_broker import request

from credential_broker.cli import bootstrap
from credential_broker.config import load_config
from credential_broker.limits import Limits
from credential_broker.models import BrokerError, Connection, Principal, Route
from credential_broker.vault import FileKeyProvider, Vault


def key(path):
    path.write_bytes(secrets.token_bytes(32))
    path.chmod(0o600)
    return FileKeyProvider(path)


def test_wrong_key_startup_and_live_file_replacement(tmp_path):
    keys = key(tmp_path / "key")
    vault = Vault(tmp_path / "data" / "db", keys)
    original = keys.key()
    record = Connection("fixture", ("agent",), "synthetic-secret-123")
    vault.put("alice", "one", record)
    key(keys.path)
    with pytest.raises(BrokerError):
        Vault(vault.path, keys)
    # The running process uses its startup key, never silently switches to a new file.
    vault.put("alice", "two", record)
    keys.path.write_bytes(original)
    restarted = Vault(vault.path, keys)
    assert restarted.get("alice", "one") == restarted.get("alice", "two") == record


def test_rekey_and_stale_process_fail_closed(tmp_path):
    old, new = key(tmp_path / "old"), key(tmp_path / "new")
    vault = Vault(tmp_path / "data" / "db", old)
    record = Connection("fixture", ("agent",), "synthetic-secret-123")
    vault.put("alice", "one", record)
    stale = Vault(vault.path, old)
    vault.rekey(new)
    with pytest.raises(BrokerError):
        stale.put("alice", "two", record)
    with pytest.raises(BrokerError):
        Vault(vault.path, old)
    assert Vault(vault.path, new).get("alice", "one") == record


def test_rekey_rolls_back_on_corrupt_record(tmp_path):
    old, new = key(tmp_path / "old"), key(tmp_path / "new")
    vault = Vault(tmp_path / "data" / "db", old)
    record = Connection("fixture", ("agent",), "synthetic-secret-123")
    vault.put("alice", "one", record)
    vault.put("alice", "two", record)
    with sqlite3.connect(vault.path) as db:
        db.execute("UPDATE connections SET ciphertext=? WHERE id='two'", (b"corrupt",))
    with pytest.raises(BrokerError):
        vault.rekey(new)
    assert Vault(vault.path, old).get("alice", "one") == record


@pytest.mark.parametrize("action", ["put", "delete"])
def test_admin_changes_roll_back_when_audit_fails(tmp_path, monkeypatch, action):
    vault = Vault(tmp_path / "data" / "db", key(tmp_path / "key"))
    original = Connection("fixture", ("agent",), "synthetic-secret-123")
    vault.put("alice", "one", original)

    def fail(*args):
        raise sqlite3.OperationalError("simulated audit failure")

    monkeypatch.setattr(vault, "_audit", fail)
    with pytest.raises(sqlite3.OperationalError):
        if action == "put":
            vault.put("alice", "one", Connection("fixture", ("other",), "replacement-secret-123"))
        else:
            vault.delete("alice", "one")
    assert vault.get("alice", "one") == original


def test_backup_restore_preserves_encrypted_credentials(tmp_path):
    keys = key(tmp_path / "key")
    vault = Vault(tmp_path / "data" / "db", keys)
    record = Connection("fixture", ("agent",), "synthetic-secret-123")
    vault.put("alice", "one", record)
    target = tmp_path / "restore"
    target.mkdir(mode=0o700)
    destination = target / "db"
    destination.touch(mode=0o600)
    with sqlite3.connect(vault.path) as source, sqlite3.connect(destination) as backup:
        source.backup(backup)
    assert Vault(destination, keys).get("alice", "one") == record
    assert record.secret.encode() not in destination.read_bytes()


def test_reject_special_key_files_without_blocking(tmp_path):
    fifo = tmp_path / "key"
    os.mkfifo(fifo, mode=0o600)
    with pytest.raises(ValueError):
        FileKeyProvider(fifo).key()


def test_configuration_permissions_duplicates_and_test_mode(tmp_path):
    root = tmp_path / "secrets"
    bootstrap(root)
    path = root / "config.json"
    assert load_config(path)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        load_config(path)
    path.chmod(0o600)
    original = path.read_text()
    path.write_text('{"identities":{},"identities":{},"providers":{}}')
    with pytest.raises(ValueError):
        load_config(path)
    config = json.loads(original)
    config["providers"]["github"]["allow_loopback_http"] = True
    with pytest.raises(ValueError):
        path.write_text(json.dumps(config))
        load_config(path)


def test_concurrency_budget_release_and_principal_isolation():
    alice, bob = Principal("alice", "agent"), Principal("bob", "agent")
    limits = Limits([alice, bob], concurrent=2, per_principal=1)
    with limits.admit(alice):
        with pytest.raises(BrokerError):
            with limits.admit(alice):
                pytest.fail("overbudget admitted")
        with limits.admit(bob):
            assert limits._active == 2
    with limits.admit(alice):
        assert limits._active == 1


def test_http_budget_rejection_never_dispatches(system):
    system["app"].state.limits._states[("alice", "agent")][1] = 0
    result = request(system)
    assert result.status_code == 429
    assert system["state"]["calls"] == []


def test_dispatch_audit_failure_prevents_provider_call(system, monkeypatch):
    def fail(*args):
        raise sqlite3.OperationalError("simulated full disk")

    monkeypatch.setattr(system["vault"], "audit", fail)
    assert request(system).status_code == 500
    assert system["state"]["calls"] == []


def test_concurrent_http_requests_are_all_accounted_for(system):
    # Exercise real transport concurrency and SQLite writes, staying below per-principal limits.
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: request(system), range(4)))
    assert all(r.status_code == 200 for r in results)
    assert len(system["state"]["calls"]) == 4
    with sqlite3.connect(system["vault"].path) as db:
        assert (
            db.execute("SELECT COUNT(*) FROM audit WHERE event='request_finished'").fetchone()[0]
            == 4
        )


def test_duplicate_authorization_headers_rejected(system):
    token = system["tokens"]["agent"]
    result = system["client"].post(
        "/v1/connections/calendar/request",
        headers=[("Authorization", "Bearer " + token), ("Authorization", "Bearer " + token)],
        json={"method": "GET", "path": "/ok"},
    )
    assert result.status_code == 401 and system["state"]["calls"] == []


@pytest.mark.parametrize("system", [True], indirect=True)
def test_untrusted_tls_provider_never_receives_credential(system):
    result = request(system)
    assert result.status_code == 502
    assert result.json()["error"] == "provider_request_failed"
    assert system["state"]["calls"] == []


def test_connection_quota_and_audit_retention(tmp_path):
    vault = Vault(tmp_path / "data" / "db", key(tmp_path / "key"))
    record = Connection("fixture", ("agent",), "synthetic-secret-123")
    vault.put("alice", "one", record)
    # Populate capacity directly; this test concerns count enforcement, not payload validity.
    with sqlite3.connect(vault.path) as db:
        db.executemany(
            "INSERT INTO connections VALUES (?,?,?,?)",
            [("alice", f"slot-{i}", b"", b"") for i in range(999)],
        )
        db.execute(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100005) INSERT INTO audit(tenant,event) SELECT 'alice','fixture' FROM n"
        )
    with pytest.raises(BrokerError, match="connection_quota_exceeded"):
        vault.put("alice", "overflow", record)
    vault.put("alice", "one", record)  # Rotation remains available at capacity.
    with sqlite3.connect(vault.path) as db:
        assert db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 100000


@pytest.mark.parametrize("change", ["origin", "routes", "auth"])
def test_provider_configuration_drift_never_sends_existing_credential(system, change):
    broker = system["broker"]
    policy = broker.providers["fixture"]
    if change == "origin":
        changed = replace(policy, origin="https://other.example.test")
    elif change == "routes":
        changed = replace(policy, routes=policy.routes + (Route("DELETE", "/event"),))
    else:
        changed = replace(policy, auth_header="X-API-Key", auth_prefix="")
    broker.providers["fixture"] = changed
    result = request(system)
    assert result.status_code == 409
    assert system["state"]["calls"] == []
    if change == "routes":
        assert system["provision"]().status_code == 200
        assert request(system).status_code == 200
