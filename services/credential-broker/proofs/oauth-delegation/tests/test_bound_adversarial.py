from __future__ import annotations

import asyncio
import secrets

import httpx
import pytest
from bound_helpers import BoundHarness
from credential_broker.delegation import statements
from credential_broker.delegation._profile import ISSUER, Denied
from credential_broker.delegation.api import application
from credential_broker.delegation.crypto import dpop, sign, verify
from credential_broker.delegation.delegation import DELEGATION
from credential_broker.delegation.execution import execute
from fastapi.testclient import TestClient


@pytest.fixture
def b(tmp_path):
    h = BoundHarness(tmp_path)
    h.start()
    return h


@pytest.mark.parametrize(
    "mutation",
    [
        "untrusted_root",
        "other_request",
        "other_delegate",
        "escalated_depth",
        "wrong_parent",
        "expiry_extension",
        "wrong_action",
        "cycle",
    ],
)
def test_delegation_substitution_denied(b, mutation):
    root = b.keys["outsider"] if mutation == "untrusted_root" else b.keys["owner"]
    first = statements.delegate(
        root, b.keys["reviewer"].thumbprint(), ISSUER, b.pending["request_sha256"], depth=1, ttl=120
    )
    claims, _ = verify(first, DELEGATION)
    if mutation == "other_request":
        claims["request_sha256"] = "different"
    if mutation == "other_delegate":
        claims["may_act"] = {"sub": b.keys["outsider"].thumbprint()}
    if mutation == "escalated_depth":
        claims["depth"] = 3
    if mutation == "wrong_parent":
        claims["parent_sha256"] = "different"
    if mutation == "wrong_action":
        claims["actions"] = ["execute"]
    if mutation == "cycle":
        claims["may_act"] = {"sub": root.thumbprint()}
    first = sign(root, DELEGATION, claims)
    chain = [first]
    approver = b.keys["reviewer"]
    if mutation == "expiry_extension":
        second = statements.delegate(
            approver,
            b.keys["outsider"].thumbprint(),
            ISSUER,
            b.pending["request_sha256"],
            parent=first,
            depth=0,
            ttl=180,
        )
        chain.append(second)
        approver = b.keys["outsider"]
    decision = statements.approve(
        approver, ISSUER, b.identifier, b.pending["request_sha256"], chain
    )
    response = b.http.post(
        "/approvals", json={"request_id": b.identifier, "statement": decision, "chain": chain}
    )
    assert response.status_code == 403 and not b.executor.calls


def test_two_delegated_hops_work_with_decreasing_depth(b):
    first = statements.delegate(
        b.keys["owner"],
        b.keys["reviewer"].thumbprint(),
        ISSUER,
        b.pending["request_sha256"],
        depth=1,
        ttl=180,
    )
    second = statements.delegate(
        b.keys["reviewer"],
        b.keys["outsider"].thumbprint(),
        ISSUER,
        b.pending["request_sha256"],
        parent=first,
        depth=0,
        ttl=120,
    )
    chain = [first, second]
    approval = statements.approve(
        b.keys["outsider"], ISSUER, b.identifier, b.pending["request_sha256"], chain
    )
    response = b.http.post(
        "/approvals", json={"request_id": b.identifier, "statement": approval, "chain": chain}
    )
    assert response.json()["callback_delivered"]
    token = b.redeem().json()["access_token"]
    assert b.execute(token).status_code == 200


def test_callback_delivery_failure_keeps_signed_outbox_for_retry(b):
    class Failed:
        async def send(self, destination, statement):
            raise OSError("transport failure")

    b.http = TestClient(application(b.service, b.executor, Failed()), base_url=ISSUER)
    response = b.approve()
    assert response.status_code == 200 and not response.json()["callback_delivered"]
    destination, callback = b.service.callback(b.identifier)
    b.restart()
    assert b.service.callback(b.identifier) == (destination, callback)
    asyncio.run(b.callbacks.send(destination, callback))
    with b.inbox.store.transaction() as db:
        assert b.inbox.store.load(db, b.identifier)["callback"] == callback


def test_callback_transport_does_not_follow_redirects(b):
    from credential_broker.delegation.transport import HttpCallbacks

    called = []

    def transport(request):
        called.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://evil.example"})

    sender = HttpCallbacks((b.url,), transport=httpx.MockTransport(transport))
    with pytest.raises(Denied):
        asyncio.run(sender.send(b.url, "signed-message"))
    assert called == [b.url]
    with pytest.raises(Denied):
        asyncio.run(sender.send("https://unregistered.example", "signed-message"))


def test_cancellation_after_consumption_never_reopens_grant(b):
    b.approve()
    token = b.redeem().json()["access_token"]

    class Cancelled:
        async def execute(self, *args, **kwargs):
            raise asyncio.CancelledError()

    from conftest import CALL

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(execute(b.service, Cancelled(), token, b.execution_proof(token), CALL))
    b.restart()
    assert b.execute(token).status_code == 403
    with b.service.store.transaction() as db:
        row = b.service.store.load(db, b.identifier)
    receipt, _ = verify(row["result"], "schemen-result+jwt", expected=b.keys["service"])
    assert receipt["outcome"] == "unknown" and row["status"] == "consumed"


@pytest.mark.parametrize(
    "field,value",
    [
        ("resource", "https://evil.example"),
        ("client_id", "other"),
        ("subject_token_type", "unknown"),
        ("grant_type", "other"),
    ],
)
def test_exchange_fields_bound(b, field, value):
    b.approve()
    form = b.form()
    form[field] = value
    assert b.redeem(form).status_code == 400
    assert not b.executor.calls


def test_token_endpoint_nonce_challenge(b):
    b.approve()
    response = b.redeem(proof=dpop(b.keys["worker"], ISSUER + "/token", "wrong"))
    assert response.status_code == 400 and response.headers["dpop-nonce"] == b.pending["nonce"]
    assert b.redeem().status_code == 200


def test_real_calendar_bridge_destroys_per_call_custody(b, monkeypatch):
    from credential_broker.broker import Broker
    from credential_broker.calendar_calls import CalendarCallService
    from credential_broker.call_receipt import public_key, verify_receipt
    from credential_broker.delegation.execution import CalendarExecutor
    from credential_broker.models import Principal
    from credential_broker.vault import FileKeyProvider, Vault

    key_file = b.directory / "vault.key"
    key_file.write_bytes(secrets.token_bytes(32))
    key_file.chmod(0o600)
    vault = Vault(b.directory / "vault" / "vault.db", FileKeyProvider(key_file))
    calendar = CalendarCallService(Broker(vault, {}))
    secret = "per-call-canary-" + secrets.token_urlsafe(24)
    acquired = []

    class Source:
        def acquire(self):
            with b.service.store.transaction() as db:
                assert b.service.store.load(db, b.identifier)["status"] == "consumed"
            acquired.append(True)
            return secret

    provider_calls = []

    def provider(request):
        import json

        assert request.headers["authorization"] == "Bearer " + secret
        provider_calls.append(request)

        class Stream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield json.dumps(
                    {"id": json.loads(request.content)["id"], "status": "confirmed"}
                ).encode()

        return httpx.Response(200, stream=Stream(), headers={"Content-Type": "application/json"})

    actual_client = httpx.AsyncClient

    def client_factory(**kwargs):
        kwargs.setdefault("transport", httpx.MockTransport(provider))
        return actual_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    owned_keys = []
    actual_seal = calendar.secrets.seal

    def seal(*args):
        actual_seal(*args)
        owned_keys.append(calendar.secrets._entries[args[0]].key)

    monkeypatch.setattr(calendar.secrets, "seal", seal)
    executor = CalendarExecutor(
        calendar, Principal("alice", "admin", True), Source(), b.config.connection
    )
    failures = []
    actual_execute = executor.execute

    async def checked_execute(*args, **kwargs):
        try:
            return await actual_execute(*args, **kwargs)
        except Exception as exc:
            failures.append((type(exc).__name__, getattr(exc, "code", None)))
            raise

    monkeypatch.setattr(executor, "execute", checked_execute)
    b.http = TestClient(application(b.service, executor, b.callbacks), base_url=ISSUER)
    assert not acquired
    assert b.approve().json()["callback_delivered"]
    assert not acquired
    token = b.redeem().json()["access_token"]
    assert not acquired
    response = b.execute(token)
    assert response.status_code == 200
    output = b.inbox.result(response.json()["receipt"], b.identifier)
    assert output["outcome"] == "confirmed", (
        failures,
        len(acquired),
        len(owned_keys),
        len(provider_calls),
    )
    custody = output["custody_receipt"]
    verify_receipt(
        custody,
        public_key(calendar.receipt_key),
        custody["body"]["grant_id"],
        custody["body"]["aad_sha256"],
    )
    assert custody["body"]["credential_custody"] == "destroyed"
    assert len(provider_calls) == len(acquired) == len(owned_keys) == 1
    assert not any(owned_keys[0]) and calendar.secrets.active_count == 0
    assert secret not in response.text and secret not in token
    assert secret.encode() not in (b.directory / "flow.db").read_bytes()
    assert secret.encode() not in vault.path.read_bytes()
    assert b.execute(token).status_code == 403 and len(provider_calls) == 1
