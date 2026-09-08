from __future__ import annotations

import json
import os
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
import uvicorn

from credential_broker.api import create_app
from credential_broker.broker import Broker
from credential_broker.models import Principal, ProviderPolicy, Route, token_hash
from credential_broker.vault import FileKeyProvider, Vault


@pytest.fixture(autouse=True)
def checkout_source_for_children(monkeypatch):
    """Child CLI processes must exercise the same checkout as these tests."""
    source = str(Path(__file__).resolve().parents[1] / "src")
    existing = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv("PYTHONPATH", source + (os.pathsep + existing if existing else ""))


@pytest.fixture
def system(tmp_path, request):
    state = {"secret": secrets.token_urlsafe(32), "calls": [], "writes": 0}

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def do_PATCH(self):
            self.respond()

        def respond(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n) if n else b""
            state["calls"].append(
                {
                    "method": self.command,
                    "path": self.path,
                    "auth": self.headers.get("Authorization"),
                    "key": self.headers.get("X-API-Key"),
                    "body": body,
                }
            )
            auth = (
                self.headers.get("Authorization") == "Bearer " + state["secret"]
                or self.headers.get("X-API-Key") == state["secret"]
            )
            status = 200 if auth else 401
            payload = json.dumps({"authenticated": auth}).encode()
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/outside")
                self.end_headers()
                return
            if self.path == "/echo":
                payload = state["secret"].encode()
            if self.path == "/large":
                payload = b"x" * 1_100_000
            if self.path == "/terminal":
                payload = b"\x1b]52;c;YXR0YWNr\x07"
            if self.command == "PATCH" and auth:
                state["writes"] += 1
                payload = json.dumps({"written": json.loads(body)}).encode()
            if state.get("delay_headers"):
                time.sleep(state["delay_headers"])
            if self.command == "POST" and auth:
                state["writes"] += 1
                payload = json.dumps({"id": json.loads(body)["id"], "status": "confirmed"}).encode()
                status = state.get("calendar_status", 200)
                payload = state.get("calendar_response", payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "secret=" + state["secret"])
            self.send_header("X-Upstream-Secret", state["secret"])
            self.end_headers()
            try:
                if state.get("drip_body"):
                    for byte in payload:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(state["drip_body"])
                else:
                    self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    tls = getattr(request, "param", False)
    if tls:
        import datetime
        import ipaddress
        import ssl

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(private, hashes.SHA256())
        )
        cert_path, private_path = tmp_path / "tls.pem", tmp_path / "tls.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private_path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private_path.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, private_path)
        upstream.socket = context.wrap_socket(upstream.socket, server_side=True)
    worker = threading.Thread(target=upstream.serve_forever, daemon=True)
    worker.start()
    key_path = tmp_path / "master.key"
    key_path.write_bytes(secrets.token_bytes(32))
    key_path.chmod(0o600)
    vault = Vault(tmp_path / "data" / "vault.sqlite", FileKeyProvider(key_path))
    origin = f"{'https' if tls else 'http'}://127.0.0.1:{upstream.server_port}"
    routes = tuple(
        Route("GET", p) for p in ("/ok", "/echo", "/redirect", "/large", "/terminal")
    ) + (Route("PATCH", "/event"),)
    providers = {
        "fixture": ProviderPolicy(origin, routes, allow_loopback_http=True),
        "apikey": ProviderPolicy(origin, routes, "X-API-Key", "", True),
    }
    tokens = {
        name: secrets.token_urlsafe(32)
        for name in ("admin", "agent", "other", "bob", "bobadmin", "otherchannel")
    }
    principals = {
        "admin": Principal("alice", "admin", True),
        "agent": Principal("alice", "agent"),
        "otherchannel": Principal("alice", "agent", channel="other"),
        "other": Principal("alice", "other"),
        "bob": Principal("bob", "agent"),
        "bobadmin": Principal("bob", "admin", True),
    }
    broker = Broker(vault, providers)
    app = create_app(broker, {token_hash(tokens[n]): p for n, p in principals.items()})
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    address = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(
        uvicorn.Config(app, access_log=False, log_level="critical", proxy_headers=False)
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started
    with httpx.Client(base_url=address, trust_env=False, timeout=5) as client:

        def headers(name="agent"):
            return {"Authorization": "Bearer " + tokens[name]}

        def provision(name="admin", connection="calendar", provider="fixture", **extra):
            return client.put(
                f"/v1/connections/{connection}",
                headers=headers(name),
                json={
                    "provider": provider,
                    "subjects": ["agent"],
                    "credential": state["secret"],
                    **extra,
                },
            )

        assert provision().status_code == 200
        yield {
            "client": client,
            "headers": headers,
            "provision": provision,
            "state": state,
            "app": app,
            "broker": broker,
            "vault": vault,
            "key_path": key_path,
            "providers": providers,
            "tokens": tokens,
        }
    server.should_exit = True
    thread.join(timeout=5)
    sock.close()
    upstream.shutdown()
    upstream.server_close()
    worker.join(timeout=5)
