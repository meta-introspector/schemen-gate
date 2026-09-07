from __future__ import annotations

import json
import subprocess
import sys

from credential_broker.cli import bootstrap
from credential_broker.models import token_hash


def test_bootstrap_creates_private_random_keys_and_hashed_identities(tmp_path, capsys):
    root = tmp_path / "secrets"
    bootstrap(root)
    config = json.loads((root / "config.json").read_text())
    assert len((root / "master.key").read_bytes()) == 32
    for name in ("admin.token", "agent.token"):
        token = (root / name).read_text()
        assert len(token) >= 32 and token_hash(token) in config["identities"]
        assert token not in capsys.readouterr().out
    assert root.stat().st_mode & 0o077 == 0
    assert all(p.stat().st_mode & 0o077 == 0 for p in root.iterdir())


def test_cli_store_request_revoke_over_live_http(system, tmp_path):
    for name in ("admin", "agent"):
        p = tmp_path / (name + ".token")
        p.write_text(system["tokens"][name])
        p.chmod(0o600)
    secret = tmp_path / "provider.secret"
    secret.write_text(system["state"]["secret"])
    secret.chmod(0o600)
    port = str(system["client"].base_url.port)

    def call(command, role, *extra):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "credential_broker.cli",
                command,
                "--port",
                port,
                "--connection",
                "cli",
                "--token-file",
                str(tmp_path / (role + ".token")),
                *extra,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert system["state"]["secret"] not in result.stdout + result.stderr
        assert all(t not in result.stdout + result.stderr for t in system["tokens"].values())
        return result

    assert (
        call(
            "store",
            "admin",
            "--provider",
            "fixture",
            "--subject",
            "agent",
            "--credential-file",
            str(secret),
        ).returncode
        == 0
    )
    response = call("request", "agent", "--method", "GET", "--path", "/ok")
    assert response.returncode == 0 and json.loads(response.stdout)["authenticated"]
    terminal = call("request", "agent", "--method", "GET", "--path", "/terminal")
    assert (
        terminal.returncode == 0 and "\x1b" not in terminal.stdout and "\\u001b" in terminal.stdout
    )
    assert call("revoke", "admin").returncode == 0
    assert call("request", "agent", "--method", "GET", "--path", "/ok").returncode == 1
