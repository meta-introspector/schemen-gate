from __future__ import annotations

import base64
import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from bound_helpers import BoundHarness
from credential_broker.delegation import statements
from credential_broker.delegation._profile import ISSUER, RESOURCE, Denied
from credential_broker.delegation.client import Inbox
from credential_broker.delegation.crypto import dpop, envelope, sign, verify
from credential_broker.delegation.demo import CALL, DETAILS
from credential_broker.delegation.service import CALLBACK, REQUEST, Service
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@pytest.fixture
def b(tmp_path):
    return BoundHarness(tmp_path)


@pytest.mark.parametrize("delegated", [False, True])
def test_signed_hops_roundtrip_and_independent_ed25519_verification(b, delegated):
    b.start()
    assert not b.executor.calls
    approval = b.approve(delegated)
    assert approval.json()["callback_delivered"] is True
    token_response = b.redeem()
    assert token_response.status_code == 200, token_response.text
    token = token_response.json()["access_token"]
    result = b.execute(token)
    assert result.status_code == 200, result.text
    receipt = b.inbox.result(result.json()["receipt"], b.identifier)
    assert receipt["outcome"] == "confirmed" and receipt["authority"] == "consumed"
    assert len(b.executor.calls) == 1
    assert b.execute(token).status_code == 403
    # Independent raw cryptography verification, not joserfc's verification function.
    pairs = [
        (b.request, "worker"),
        (b.approval, "reviewer" if delegated else "owner"),
        (b.service.callback(b.identifier)[1], "service"),
        (token, "service"),
        (result.json()["receipt"], "service"),
        (b.execution_proof(token), "worker"),
    ]
    pairs.extend((delegation, "owner") for delegation in b.chain)
    for encoded, signer in pairs:
        h, p, signature = encoded.split(".")
        x = b.keys[signer].as_dict(private=False)["x"]
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
        Ed25519PublicKey.from_public_bytes(raw).verify(
            base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
            (h + "." + p).encode(),
        )


def test_self_created_identity_cannot_approve_its_own_claims(b):
    request = statements.request(
        b.keys["outsider"],
        ISSUER,
        RESOURCE,
        "outsider",
        DETAILS,
        tenant=b.config.tenant,
        connection=b.config.connection,
    )
    response = b.http.post("/requests", json={"statement": request})
    assert response.status_code == 200
    ack, _ = verify(response.json()["pending"], "schemen-pending+jwt", expected=b.keys["service"])
    approval = statements.approve(
        b.keys["outsider"], ISSUER, ack["request_id"], ack["request_sha256"], []
    )
    result = b.http.post(
        "/approvals", json={"request_id": ack["request_id"], "statement": approval, "chain": []}
    )
    assert result.status_code == 403 and not b.executor.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("iss", "owner"),
        ("aud", "https://evil.example"),
        ("resource", "https://evil.example"),
        ("callback_id", "outsider"),
        ("exp", 1),
        ("nonce", "short"),
        ("unknown", "owner"),
    ],
)
def test_request_binding_substitution_rejected(b, field, value):
    original = statements.request(
        b.keys["worker"],
        ISSUER,
        RESOURCE,
        "worker",
        DETAILS,
        tenant=b.config.tenant,
        connection=b.config.connection,
    )
    claims, _ = verify(original, REQUEST)
    claims[field] = value
    altered = sign(b.keys["worker"], REQUEST, claims)
    assert b.http.post("/requests", json={"statement": altered}).status_code == 403


def test_request_replay_survives_restart(b):
    b.start()
    b.restart()
    assert b.http.post("/requests", json={"statement": b.request}).status_code == 403


def test_callback_is_pinned_to_service_and_pending_request(b):
    b.start()
    assert b.approve().status_code == 200
    original = b.service.callback(b.identifier)[1]
    # Exact retries are idempotent, including after inbox restart.
    again = Inbox(
        ISSUER, b.keys["service"], b.keys["worker"], b.url, b.directory / "inbox.db", b.inbox_key
    )
    again.receive(original)
    claims, _ = verify(original, CALLBACK)
    forged = sign(b.keys["outsider"], CALLBACK, claims)
    with pytest.raises(Denied):
        again.receive(forged)


@pytest.mark.parametrize(
    "field,value",
    [
        ("aud", "https://other.example/callback"),
        ("cnf", {"jkt": "other"}),
        ("caller_nonce", "different"),
        ("request_sha256", "different"),
        ("request_id", "x" * 24),
        ("resource", "https://other.example"),
        ("exp", 1),
    ],
)
def test_even_service_signed_wrong_callback_binding_denied(b, field, value):
    b.start()
    b.approve()
    claims, _ = verify(b.service.callback(b.identifier)[1], CALLBACK)
    claims[field] = value
    with pytest.raises(Denied):
        b.inbox.receive(sign(b.keys["service"], CALLBACK, claims))


def test_stolen_callback_and_actor_token_do_not_authorize_other_key(b):
    b.start()
    b.approve()
    response = b.redeem(form=b.form(b.keys["outsider"]))
    assert response.status_code == 400 and not b.executor.calls


def test_token_exchange_and_action_budget_survive_restart(b):
    token = b.ready()
    b.restart()
    assert b.redeem().status_code == 400
    assert b.execute(token).status_code == 200
    b.restart()
    assert b.execute(token).status_code == 403 and len(b.executor.calls) == 1


def test_changed_body_fails_real_gate_before_effect(b):
    token = b.ready()
    changed = copy.deepcopy(CALL)
    changed["event"]["summary"] = "Unapproved"
    assert b.execute(token, call=changed).json()["error"] == "operation_denied"
    assert not b.executor.calls
    assert b.execute(token).status_code == 200


def test_resource_nonce_challenge_and_key_binding(b):
    token = b.ready()
    challenge = b.execute(token, proof=b.execution_proof(token, "wrong"))
    assert challenge.status_code == 401
    nonce = challenge.headers["dpop-nonce"]
    stolen = dpop(b.keys["outsider"], RESOURCE, nonce, token)
    assert b.execute(token, proof=stolen).status_code == 403
    assert not b.executor.calls
    assert b.execute(token, proof=b.execution_proof(token, nonce)).status_code == 200


def test_concurrent_service_instances_consume_one_budget(b):
    token = b.ready()
    from credential_broker.delegation.api import application
    from fastapi.testclient import TestClient

    other = Service(b.config, b.keys["service"], b.gate_key, b.directory / "flow.db")
    client = TestClient(application(other, b.executor, b.callbacks), base_url=ISSUER)

    def call(index):
        target = b.http if index % 2 else client
        return target.post(
            RESOURCE,
            json={"call": CALL},
            headers={"Authorization": "DPoP " + token, "DPoP": b.execution_proof(token)},
        ).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(call, range(8)))
    assert statuses.count(200) == 1 and len(b.executor.calls) == 1


def test_root_revocation_invalidates_issued_grant(b):
    token = b.ready()
    statement = statements.approve(
        b.keys["owner"], ISSUER, b.identifier, b.pending["request_sha256"], [], decision="deny"
    )
    response = b.http.post(
        "/revocations", json={"request_id": b.identifier, "statement": statement, "chain": []}
    )
    assert response.status_code == 200
    assert b.execute(token).status_code == 403 and not b.executor.calls


def test_denial_never_becomes_execution_authority(b):
    b.start()
    assert b.approve(decision="deny").json()["callback_delivered"]
    assert b.redeem().status_code == 400 and not b.executor.calls


def test_state_is_encrypted_and_tampering_fails_closed(b):
    token = b.ready()
    data = (b.directory / "flow.db").read_bytes()
    assert CALL["event"]["summary"].encode() not in data
    assert token.encode() not in data
    with sqlite3.connect(b.directory / "flow.db") as db:
        db.execute("UPDATE requests SET data=zeroblob(100) WHERE id=?", (b.identifier,))
    assert (
        b.execute(token, proof=dpop(b.keys["worker"], RESOURCE, "nonce", token)).status_code == 403
    )
    assert not b.executor.calls


def test_configuration_or_key_substitution_on_restart_fails(b):
    b.start()
    with pytest.raises(Denied):
        Service(
            replace(b.config, connection="other"),
            b.keys["service"],
            b.gate_key,
            b.directory / "flow.db",
        )
    with pytest.raises(Denied):
        Service(b.config, b.keys["outsider"], b.gate_key, b.directory / "flow.db")


def test_signed_result_can_be_retrieved_only_by_bound_caller(b):
    token = b.ready()
    receipt = b.execute(token).json()["receipt"]
    for who, expected in (("outsider", 403), ("worker", 200)):
        key = b.keys[who]
        statement = sign(
            key,
            "schemen-result-request+jwt",
            {**envelope(key, ISSUER + "/results"), "request_id": b.identifier},
        )
        response = b.http.post("/results", json={"statement": statement})
        assert response.status_code == expected
        if expected == 200:
            assert response.json()["receipt"] == receipt
