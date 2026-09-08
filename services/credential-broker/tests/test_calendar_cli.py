from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from test_calendar_calls import calendar_system as calendar_system
from test_calendar_calls import proposal

import credential_broker.calendar_calls as call_module
from credential_broker.calendar_cli import _read_document, add_commands
from credential_broker.call_receipt import verify_receipt


def private_file(path: Path, value: str) -> Path:
    path.write_text(value)
    path.chmod(0o600)
    return path


@pytest.fixture
def calendar_cli(calendar_system: dict[str, Any], tmp_path: Path):
    system = calendar_system
    for name in ("admin", "agent"):
        private_file(tmp_path / (name + ".token"), system["tokens"][name])
    credential = private_file(tmp_path / "provider.secret", system["state"]["secret"])
    call_file = private_file(tmp_path / "call.json", json.dumps(proposal()))
    grant_file = tmp_path / "grant.json"

    def cli(command: str, role: str, *extra: str):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "credential_broker.cli",
                command,
                "--port",
                str(system["client"].base_url.port),
                "--token-file",
                str(tmp_path / (role + ".token")),
                "--grant-file",
                str(grant_file),
                *extra,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for value in [system["state"]["secret"], *system["tokens"].values()]:
            assert value not in result.stdout + result.stderr
        return result

    def approve():
        return cli(
            "calendar-approve",
            "admin",
            "--credential-file",
            str(credential),
            "--subject",
            "agent",
            "--channel",
            "default",
            "--call-file",
            str(call_file),
        )

    return {"system": system, "approve": approve, "cli": cli, "grant_file": grant_file}


def test_calendar_cli_approve_execute_and_verified_receipt(calendar_cli):
    fixture = calendar_cli
    approved = fixture["approve"]()
    assert approved.returncode == 0, approved.stderr
    grant = json.loads(fixture["grant_file"].read_text())
    assert approved.stdout.strip() == grant["grant_id"]
    assert "gate" not in approved.stdout
    assert fixture["grant_file"].stat().st_mode & 0o077 == 0
    assert fixture["system"]["state"]["secret"] not in fixture["grant_file"].read_text()
    assert grant["receipt_key"] == fixture["system"]["pinned_receipt_key"]
    executed = fixture["cli"]("calendar-execute", "agent")
    assert executed.returncode == 0, executed.stderr
    output = json.loads(executed.stdout)
    assert set(output) == {"event_id", "outcome", "receipt"}
    assert output["event_id"] == grant["call"]["event"]["id"]
    assert output["outcome"] == "confirmed"
    assert (
        verify_receipt(
            output["receipt"], grant["receipt_key"], grant["grant_id"], grant["aad_sha256"]
        )["outcome"]
        == "confirmed"
    )
    assert len(fixture["system"]["state"]["calls"]) == 1
    replay = fixture["cli"]("calendar-execute", "agent")
    assert replay.returncode == 1
    assert replay.stdout == ""
    assert "Traceback" not in replay.stderr
    assert len(fixture["system"]["state"]["calls"]) == 1


def test_calendar_cli_grant_output_never_overwrites_or_mints_again(calendar_cli):
    fixture = calendar_cli
    assert fixture["approve"]().returncode == 0
    before = fixture["grant_file"].read_bytes()
    result = fixture["approve"]()
    assert result.returncode == 1
    assert result.stdout == ""
    assert fixture["grant_file"].read_bytes() == before
    with sqlite3.connect(fixture["system"]["vault"].path) as database:
        assert database.execute("SELECT COUNT(*) FROM calendar_calls").fetchone()[0] == 1


def test_calendar_cli_refuses_receipt_with_changed_pinned_key(calendar_cli):
    fixture = calendar_cli
    assert fixture["approve"]().returncode == 0
    grant = json.loads(fixture["grant_file"].read_text())
    grant["receipt_key"] = "00" * 32
    fixture["grant_file"].write_text(json.dumps(grant))
    result = fixture["cli"]("calendar-execute", "agent")
    assert result.returncode == 1
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    # Receipt verification happens after execution. A verification failure must
    # never be interpreted as permission to repeat the provider write.
    assert len(fixture["system"]["state"]["calls"]) == 1
    assert fixture["cli"]("calendar-execute", "agent").returncode == 1
    assert len(fixture["system"]["state"]["calls"]) == 1


def test_calendar_cli_rejects_validly_signed_receipt_for_different_event(calendar_cli, monkeypatch):
    fixture = calendar_cli
    assert fixture["approve"]().returncode == 0
    signer = call_module.sign_receipt

    def wrong_event(key, body):
        return signer(key, {**body, "event_id": "differentapprovedevent"})

    monkeypatch.setattr(call_module, "sign_receipt", wrong_event)
    result = fixture["cli"]("calendar-execute", "agent")
    assert result.returncode == 1
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert len(fixture["system"]["state"]["calls"]) == 1


@pytest.mark.parametrize("status", [200, 401])
def test_calendar_cli_only_prints_verified_projection_of_provider_response(calendar_cli, status):
    fixture = calendar_cli
    assert fixture["approve"]().returncode == 0
    grant = json.loads(fixture["grant_file"].read_text())
    canary = "private-provider-response-7c39b1"
    fixture["system"]["state"]["calendar_status"] = status
    fixture["system"]["state"]["calendar_response"] = json.dumps(
        {
            "id": grant["call"]["event"]["id"],
            "status": "confirmed",
            "private_result": canary + "\x1b[31m",
        }
    ).encode()
    result = fixture["cli"]("calendar-execute", "agent")
    assert result.returncode == (0 if status == 200 else 1)
    assert canary not in result.stdout + result.stderr
    assert "\x1b" not in result.stdout + result.stderr
    output = json.loads(result.stdout)
    assert output["outcome"] == ("confirmed" if status == 200 else "provider_rejected")
    assert set(output) == {"event_id", "outcome", "receipt"}
    assert (
        verify_receipt(
            output["receipt"], grant["receipt_key"], grant["grant_id"], grant["aad_sha256"]
        )["provider_status"]
        == status
    )


def test_calendar_cli_private_json_can_exceed_legacy_secret_limit(tmp_path):
    path = private_file(tmp_path / "large-grant.json", json.dumps({"value": "x" * 9000}))
    assert _read_document(path) == {"value": "x" * 9000}


@pytest.mark.parametrize("kind", ["public", "symlink", "fifo", "oversize", "duplicate", "array"])
def test_calendar_cli_rejects_unsafe_or_ambiguous_documents(tmp_path, kind):
    path = tmp_path / "document.json"
    if kind == "fifo":
        os.mkfifo(path, mode=0o600)
    elif kind == "symlink":
        target = private_file(tmp_path / "target.json", "{}")
        path.symlink_to(target)
    else:
        raw = {"oversize": "x" * 65537, "duplicate": '{"id":1,"id":2}', "array": "[]"}.get(
            kind, "{}"
        )
        private_file(path, raw)
        if kind == "public":
            path.chmod(0o644)
    with pytest.raises((ValueError, OSError)):
        _read_document(path)


def test_calendar_cli_parser_has_explicit_one_call_defaults():
    parser = argparse.ArgumentParser()
    add_commands(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args(
        [
            "calendar-approve",
            "--token-file",
            "admin",
            "--grant-file",
            "grant",
            "--credential-file",
            "credential",
            "--call-file",
            "call",
            "--subject",
            "agent",
            "--channel",
            "default",
        ]
    )
    assert args.port == 8787
    assert args.expires_in == 60
