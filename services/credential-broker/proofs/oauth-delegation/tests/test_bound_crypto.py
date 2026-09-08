from __future__ import annotations

import time

import pytest
from bound_helpers import BoundHarness
from credential_broker.delegation._profile import ISSUER
from credential_broker.delegation.crypto import envelope, sign, verify
from credential_broker.delegation.service import REQUEST
from joserfc import jwt


@pytest.fixture
def b(tmp_path):
    return BoundHarness(tmp_path)


@pytest.mark.parametrize("field,value", [("tenant", "other"), ("connection", "other")])
def test_account_binding_is_signed_by_initial_caller(b, field, value):
    b.start()
    claims, _ = verify(b.request, REQUEST)
    claims[field] = value
    assert (
        b.http.post(
            "/requests", json={"statement": sign(b.keys["worker"], REQUEST, claims)}
        ).status_code
        == 403
    )


def test_owner_can_review_but_self_asserted_outsider_cannot(b):
    b.start()
    for who, expected in (("outsider", 403), ("owner", 200)):
        key = b.keys[who]
        statement = sign(
            key,
            "schemen-review-request+jwt",
            {**envelope(key, ISSUER + "/reviews"), "request_id": b.identifier},
        )
        response = b.http.post("/reviews", json={"statement": statement, "chain": []})
        assert response.status_code == expected
        if expected == 200:
            claims, _ = verify(
                response.json()["review"], "schemen-review+jwt", expected=b.keys["service"]
            )
            assert (
                claims["request"] == b.request
                and claims["request_sha256"] == b.pending["request_sha256"]
            )


def test_signature_domain_cannot_be_substituted(b):
    b.start()
    claims, _ = verify(b.request, REQUEST)
    for kind in ("JWT", "dpop+jwt", "schemen-approval+jwt", "schemen-callback+jwt"):
        statement = sign(b.keys["worker"], kind, claims)
        assert b.http.post("/requests", json={"statement": statement}).status_code == 403


def test_deprecated_eddsa_identifier_is_not_silently_accepted(b):
    b.start()
    claims, _ = verify(b.request, REQUEST)
    public = b.keys["worker"].as_dict(private=False)
    with pytest.warns(Warning):
        statement = jwt.encode(
            {"alg": "EdDSA", "typ": REQUEST, "jwk": public},
            claims,
            b.keys["worker"],
            algorithms=["EdDSA"],
        )
    assert b.http.post("/requests", json={"statement": statement}).status_code == 403


@pytest.mark.parametrize(
    "field,value",
    [
        ("htm", "GET"),
        ("htu", "https://other.example"),
        ("iat", 1),
        ("iat", True),
        ("jti", "short"),
        ("ath", "wrong"),
    ],
)
def test_ed25519_dpop_claims_are_enforced(b, field, value):
    token = b.ready()
    original = b.execution_proof(token)
    claims, _ = verify(original, "dpop+jwt")
    claims[field] = value
    altered = sign(b.keys["worker"], "dpop+jwt", claims)
    assert b.execute(token, proof=altered).status_code == 403 and not b.executor.calls


def test_malformed_requests_do_not_escape_as_server_errors(b):
    for value in (None, [], {"statement": None}, {"statement": 2}, {"statement": ""}):
        response = b.http.post("/requests", json=value)
        assert response.status_code in {400, 403}
    assert (
        b.http.post(
            "/token",
            content="broken",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ).status_code
        == 400
    )


def test_client_assertion_expiry_and_replay_are_enforced(b):
    b.start()
    b.approve()
    form = b.form()
    claims, _ = verify(form["client_assertion"], "JWT")
    claims["exp"] = int(time.time()) - 1
    form["client_assertion"] = sign(b.keys["worker"], "JWT", claims)
    assert b.redeem(form).status_code == 400
    fresh = b.form()
    assert b.redeem(fresh).status_code == 200
    b.restart()
    assert b.redeem(fresh).status_code == 400


def test_bad_subject_token_uses_token_exchange_error_code(b):
    b.start()
    b.approve()
    form = b.form()
    form["subject_token"] = "not-a-token"
    assert b.redeem(form).json()["error"] == "invalid_request"


@pytest.mark.parametrize(
    "field,value", [("event_id", "unapproved-event"), ("event_id", None), ("authority", "pending")]
)
def test_caller_rejects_inconsistent_signed_result(b, field, value):
    token = b.ready()
    response = b.execute(token)
    claims, _ = verify(response.json()["receipt"], "schemen-result+jwt", expected=b.keys["service"])
    claims[field] = value
    from credential_broker.delegation._profile import Denied

    with pytest.raises(Denied):
        b.inbox.result(sign(b.keys["service"], "schemen-result+jwt", claims), b.identifier)
