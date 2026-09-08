from __future__ import annotations

import copy
import time

import jwt
import pytest
from conftest import CALL, ClientKey
from credential_broker.models import BrokerError

from oauth_proof.exchange import execute
from oauth_proof.jose import Proofs
from oauth_proof.profile import RESOURCE, TOKEN_URL, Denied


@pytest.mark.parametrize(
    "field,value",
    [
        ("htm", "GET"),
        ("htu", "https://other.example/calendar/execute"),
        ("iat", 1),
        ("iat", 99999999999),
        ("iat", True),
        ("ath", "wrong"),
        ("jti", ""),
        ("jti", 10),
        ("nonce", "wrong"),
    ],
)
def test_bad_resource_proofs_cause_zero_effects(h, field, value):
    token = h.ready()
    proof = h.keys["worker"].proof(
        RESOURCE, h.authority.nonces["resource"], token, **{field: value}
    )
    assert h.execute(token, proof=proof).status_code == 401
    assert h.authority.provider_calls == []


def test_stolen_access_token_without_bound_key_is_useless(h):
    token = h.ready()
    proof = h.keys["outsider"].proof(RESOURCE, h.authority.nonces["resource"], token)
    assert h.execute(token, proof=proof).json()["error"] == "invalid_dpop_proof"
    assert h.authority.provider_calls == []


def test_bearer_downgrade_denied(h):
    token = h.ready()
    assert h.execute(token, scheme="Bearer").status_code == 401
    assert h.authority.provider_calls == []


@pytest.mark.parametrize("field", ["htm", "htu", "iat", "jti", "ath"])
def test_required_claim_cannot_be_missing(h, field):
    token = h.ready()
    proof = h.keys["worker"].proof(RESOURCE, h.authority.nonces["resource"], token)
    payload = jwt.decode(proof, options={"verify_signature": False})
    del payload[field]
    altered = jwt.encode(
        payload,
        h.keys["worker"].key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": h.keys["worker"].public},
    )
    assert h.execute(token, proof=altered).status_code == 401
    assert h.authority.provider_calls == []


@pytest.mark.parametrize("mutation", ["typ", "private", "signature", "none", "symmetric", "jku"])
def test_jose_confusion_denied(h, mutation):
    token = h.ready()
    key = h.keys["worker"]
    good = key.proof(RESOURCE, h.authority.nonces["resource"], token)
    payload = jwt.decode(good, options={"verify_signature": False})
    headers = {"typ": "dpop+jwt", "jwk": key.public}
    signing_key = key.key
    algorithm = "ES256"
    if mutation == "typ":
        headers["typ"] = "JWT"
    elif mutation == "private":
        import json

        headers["jwk"] = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.key))
    elif mutation == "signature":
        signing_key = ClientKey().key
    elif mutation == "none":
        signing_key, algorithm = None, "none"
    elif mutation == "symmetric":
        signing_key, algorithm = b"x" * 32, "HS256"
    else:
        headers["jku"] = "https://attacker.example/keys"
    proof = jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers)
    assert h.execute(token, proof=proof).status_code == 401
    assert h.authority.provider_calls == []


def test_resource_nonce_challenge_then_fresh_proof_succeeds(h):
    token = h.ready()
    proof = h.keys["worker"].proof(RESOURCE, None, token)
    response = h.execute(token, proof=proof)
    assert response.status_code == 401 and response.json()["error"] == "use_dpop_nonce"
    assert response.headers["www-authenticate"] == 'DPoP error="use_dpop_nonce"'
    assert (
        h.execute(
            token, proof=h.keys["worker"].proof(RESOURCE, response.headers["dpop-nonce"], token)
        ).status_code
        == 200
    )


def test_token_nonce_challenge_then_fresh_proof_succeeds(h):
    root = h.root_token()
    proof = h.keys["reviewer"].proof(TOKEN_URL, None)
    response = h.exchange(root, "reviewer", proof=proof)
    assert response.status_code == 400 and response.json()["error"] == "use_dpop_nonce"
    assert (
        h.exchange(
            root,
            "reviewer",
            proof=h.keys["reviewer"].proof(TOKEN_URL, response.headers["dpop-nonce"]),
        ).status_code
        == 200
    )


def test_replayed_dpop_proof_denied_even_before_action_is_consumed(h):
    token = h.ready()
    proof = h.keys["worker"].proof(RESOURCE, h.authority.nonces["resource"], token)
    changed = copy.deepcopy(CALL)
    changed["event"]["summary"] = "Unapproved"
    assert h.execute(token, call=changed, proof=proof).status_code == 401
    assert h.execute(token, proof=proof).json()["error"] == "invalid_dpop_proof"
    assert h.authority.provider_calls == []
    assert h.execute(token).status_code == 200  # Fresh proof, original approved operation.


def test_control_dpop_alone_does_not_bind_body_but_gate_does(h):
    token = h.ready()
    proof = h.keys["worker"].proof(RESOURCE, h.authority.nonces["resource"], token)
    # Independent verifier instance accepts this proof regardless of a proposed body.
    verifier = Proofs()
    assert verifier.verify(
        proof,
        "POST",
        RESOURCE,
        nonce=h.authority.nonces["resource"],
        expected_key=h.keys["worker"].thumb,
        access_token=token,
    )
    changed = copy.deepcopy(CALL)
    changed["event"]["summary"] = "Different event"
    with pytest.raises(BrokerError) as error:
        execute(h.authority, token, proof, {"call": changed})
    assert error.value.code == "call_gate_invalid"
    assert h.authority.provider_calls == []


def test_connection_generation_is_bound_by_real_gate(h):
    token = h.ready()
    proof = h.keys["worker"].proof(RESOURCE, h.authority.nonces["resource"], token)
    with pytest.raises(BrokerError):
        execute(h.authority, token, proof, {"call": CALL}, connection="calendar-v2")
    assert h.authority.provider_calls == []


def test_duplicate_dpop_and_authorization_headers_denied(h):
    token = h.ready()
    proof = h.keys["worker"].proof(RESOURCE, h.authority.nonces["resource"], token)
    for duplicate in ("DPoP", "Authorization"):
        headers = [("Authorization", f"DPoP {token}"), ("DPoP", proof)]
        headers.append((duplicate, proof if duplicate == "DPoP" else f"DPoP {token}"))
        assert h.http.post(RESOURCE, json={"call": CALL}, headers=headers).status_code == 401
    assert h.authority.provider_calls == []


def test_same_jti_at_token_endpoint_cannot_be_replayed(h):
    root = h.root_token()
    proof = h.keys["reviewer"].proof(TOKEN_URL, h.authority.nonces["token"])
    assert h.exchange(root, "reviewer", proof=proof).status_code == 200
    another_root_token = h.authority.root_token(h.root)
    assert (
        h.exchange(another_root_token, "reviewer", proof=proof).json()["error"]
        == "invalid_dpop_proof"
    )


def test_uri_comparison_ignores_request_query_and_normalizes_host_port():
    key = ClientKey()
    proof = key.proof("https://BROKER.example:443/calendar/execute", "nonce")
    assert Proofs().verify(proof, "POST", RESOURCE + "?ignored=1", nonce="nonce") == key.thumb


def test_expired_token_denied_at_resource(h):
    token = h.ready()
    claims = jwt.decode(token, options={"verify_signature": False})
    claims["exp"] = int(time.time()) - 1
    assert h.execute(h.authority.sign(claims)).status_code == 401
    assert h.authority.provider_calls == []


def test_plain_malformed_proof_denied():
    with pytest.raises(Denied):
        Proofs().verify("not-a-jwt", "POST", RESOURCE, nonce="nonce")
