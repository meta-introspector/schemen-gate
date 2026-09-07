"""Regressions reproduced against the original repository integration."""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time

import pytest
from test_broker import request

from credential_broker import broker as broker_module
from credential_broker import cli, guard
from credential_broker.api import create_app
from credential_broker.models import Principal, token_hash


@pytest.mark.parametrize("behavior", ["delay_headers", "drip_body"])
def test_provider_absolute_deadline_closes_stalled_exchange(system, monkeypatch, behavior):
    monkeypatch.setattr(broker_module, "PROVIDER_TIMEOUT", 0.2, raising=False)
    system["state"][behavior] = 0.8 if behavior == "delay_headers" else 0.04
    started = time.monotonic()
    result = request(system)
    assert result.status_code == 502
    assert result.json()["error"] == "provider_timeout"
    assert time.monotonic() - started < 0.7
    assert system["app"].state.limits._active == 0
    system["state"].pop(behavior)
    assert request(system).status_code == 200  # Admission and transport recover.


def test_cli_malformed_token_never_prints_secret_or_traceback(system, tmp_path):
    path = tmp_path / "token"
    sentinel = "synthetic-sensitive-token-123456789"
    path.write_bytes((sentinel + "\r").encode())
    path.chmod(0o600)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "credential_broker.cli",
            "request",
            "--port",
            str(system["client"].base_url.port),
            "--token-file",
            str(path),
            "--connection",
            "calendar",
            "--method",
            "GET",
            "--path",
            "/ok",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode != 0
    assert sentinel not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert system["state"]["calls"] == []


@pytest.mark.parametrize("completion", ["sent", "timeout", "cancelled"])
def test_admission_covers_delivery_and_releases_on_failure(system, monkeypatch, completion):
    if completion == "timeout":
        monkeypatch.setattr(guard, "RESPONSE_TIMEOUT", 0.1)

    async def scenario():
        token = system["tokens"]["agent"]
        app = create_app(system["broker"], {token_hash(token): Principal("alice", "agent")})
        body_reached, release = asyncio.Event(), asyncio.Event()
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/v1/missing",
            "raw_path": b"/v1/missing",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"authorization", ("Bearer " + token).encode())],
            "server": ("127.0.0.1", 80),
            "client": ("127.0.0.1", 1),
        }

        async def receive():
            await asyncio.Event().wait()

        async def send(message):
            if message["type"] == "http.response.body":
                body_reached.set()
                await release.wait()

        task = asyncio.create_task(app(scope, receive, send))
        try:
            await asyncio.wait_for(body_reached.wait(), 2)
            assert app.state.limits._active == 1
            if completion == "timeout":
                with pytest.raises(RuntimeError, match="broker response aborted"):
                    await asyncio.wait_for(task, 2)
            elif completion == "cancelled":
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
        finally:
            release.set()
            if not task.done():
                await task
        assert app.state.limits._active == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Type", "application/json"), ("Content-Type", "application/json")],
        [("Content-Type", "application/json"), ("Content-Encoding", "gzip")],
    ],
)
def test_ambiguous_or_encoded_request_is_rejected_before_dispatch(system, headers):
    result = system["client"].post(
        "/v1/connections/calendar/request",
        headers=list(system["headers"]().items()) + headers,
        content=b'{"method":"GET","path":"/ok"}',
    )
    assert result.status_code == 415
    assert system["state"]["calls"] == []


def test_only_exact_health_operation_is_public_and_no_slash_redirects(system):
    client = system["client"]
    assert client.get("/healthz").status_code == 200
    for method, path in [("GET", "/missing"), ("GET", "/healthz/"), ("POST", "/healthz")]:
        result = client.request(method, path)
        assert result.status_code == 401
        assert result.headers["cache-control"] == "no-store"
    result = client.post("/v1/connections/calendar/request/", headers=system["headers"]())
    assert result.status_code == 404
    assert "location" not in result.headers
    assert system["state"]["calls"] == []


def test_cli_unexpected_failure_is_sanitized(monkeypatch, capsys):
    def fail():
        raise RuntimeError("synthetic-sensitive-failure-detail")

    monkeypatch.setattr(cli, "run", fail)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "sensitive" not in output.err and "Traceback" not in output.err
