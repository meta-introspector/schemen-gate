from __future__ import annotations

import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor

import jwt
import pytest
from conftest import DETAILS, Harness
from joserfc.jwk import ECKey

from oauth_proof.authority import Principal
from oauth_proof.profile import ACCESS_TYPE, ISSUER, RESOURCE, Denied


@pytest.mark.parametrize("kind", ["human", "agent"])
def test_two_hops_pause_then_execute_once_with_independent_jwt_verifier(kind):
    h = Harness(kind)
    with pytest.raises(Denied):
        h.authority.root_token(h.root)
    parent = h.root_token()
    first = h.exchange(parent, "reviewer")
    assert first.status_code == 200
    output = first.json()
    assert output["issued_token_type"] == ACCESS_TYPE and output["token_type"] == "DPoP"
    assert output["authorization_details"] == DETAILS
    assert first.headers["cache-control"] == "no-store"
    token = output["access_token"]
    assert h.execute(token).status_code == 401  # Intermediate authority cannot execute.
    assert h.exchange(token, "worker").status_code == 400  # Paused; no token issued.
    assert h.authority.provider_calls == []
    h.decide("reviewer")
    second = h.exchange(token, "worker")
    assert second.status_code == 200
    issued = second.json()["access_token"]
    public = jwt.PyJWK.from_dict(h.authority.key.as_dict(private=False)).key
    claims = jwt.decode(issued, public, algorithms=["ES256"], audience=RESOURCE, issuer=ISSUER)
    assert claims["sub"] == "owner"
    assert claims["act"] == {"sub": "worker", "act": {"sub": "reviewer"}}
    assert claims["cnf"] == {"jkt": h.keys["worker"].thumb}
    assert (
        claims["exp"] <= jwt.decode(token, public, algorithms=["ES256"], audience=RESOURCE)["exp"]
    )
    assert h.execute(issued).status_code == 200
    assert h.execute(issued).status_code == 401
    assert len(h.authority.provider_calls) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("grant_type", "authorization_code"),
        ("subject_token_type", "bad"),
        ("actor_token_type", ACCESS_TYPE),
        ("requested_token_type", "bad"),
        ("resource", "https://other.example"),
        ("subject_token", "broken"),
        ("actor_token", "broken"),
        ("extra", "unexpected"),
    ],
)
def test_invalid_exchange_never_dispatches(h, field, value):
    root = h.root_token()
    form = h.form(root, "reviewer")
    form[field] = value
    assert h.exchange(root, "reviewer", form=form).status_code == 400
    assert h.authority.provider_calls == []


@pytest.mark.parametrize("mutation", ["type", "action", "location", "event", "extra", "duplicate"])
def test_rar_cannot_widen_or_change(h, mutation):
    root = h.root_token()
    form = h.form(root, "reviewer")
    requested = copy.deepcopy(DETAILS)
    if mutation == "type":
        requested[0]["type"] = "unknown"
    elif mutation == "action":
        requested[0]["actions"].append("delete")
    elif mutation == "location":
        requested[0]["locations"] = ["https://other.example"]
    elif mutation == "event":
        requested[0]["call"]["event"]["summary"] = "Changed"
    elif mutation == "extra":
        requested[0]["uses"] = 2
    else:
        requested.append(copy.deepcopy(requested[0]))
    form["authorization_details"] = json.dumps(requested)
    result = h.exchange(root, "reviewer", form=form)
    assert result.json()["error"] == "invalid_authorization_details"
    assert h.authority.provider_calls == []


def test_authenticated_client_must_match_actor(h):
    root = h.root_token()
    assert h.exchange(root, "reviewer", auth_actor="outsider").status_code == 400


def test_unregistered_approval_and_self_approval_fail(h):
    with pytest.raises(Denied):
        h.decide("worker")
    with pytest.raises(Denied):
        h.decide("reviewer")
    fake = Principal("owner", "human", "fake-key", "fake-secret")
    with pytest.raises(Denied):
        h.authority.decide(h.root, fake, True)


def test_parent_denial_revokes_descendant(h):
    token = h.ready()
    h.authority.pending[h.root].revoked = True  # Trusted policy fixture: root revocation.
    assert h.execute(token).status_code == 401
    assert h.authority.provider_calls == []


def test_denial_and_expiry_cannot_resume(h):
    h.decide("owner", False)
    with pytest.raises(Denied):
        h.authority.root_token(h.root)
    other = Harness()
    parent = other.root_token()
    other.authority.pending[other.root].expires = int(time.time()) - 1
    assert other.exchange(parent, "reviewer").status_code == 400


def test_prior_actor_history_is_not_authorization(h):
    root = h.root_token()
    claims = jwt.decode(root, options={"verify_signature": False})
    claims["act"] = {"sub": "outsider", "act": {"sub": "owner"}}
    altered = h.authority.sign(
        claims
    )  # Even trusted signed history cannot supply current authority.
    assert h.exchange(altered, "reviewer").status_code == 400
    assert h.authority.provider_calls == []


@pytest.mark.parametrize(
    "field,value", [("iss", "https://evil.example"), ("aud", "https://other.example"), ("exp", 1)]
)
def test_signed_wrong_issuer_audience_expiry_denied(h, field, value):
    root = h.root_token()
    claims = jwt.decode(root, options={"verify_signature": False})
    claims[field] = value
    assert h.exchange(h.authority.sign(claims), "reviewer").status_code == 400


def test_unknown_signer_denied(h):
    root = h.root_token()
    claims = jwt.decode(root, options={"verify_signature": False})
    from joserfc import jwt as server_jwt

    bad = server_jwt.encode({"alg": "ES256", "typ": "JWT"}, claims, ECKey.generate_key("P-256"))
    assert h.exchange(bad, "reviewer").status_code == 400


def test_concurrent_redemption_has_one_counted_effect(h):
    token = h.ready()
    with ThreadPoolExecutor(max_workers=8) as executor:
        statuses = list(executor.map(lambda _: h.execute(token).status_code, range(8)))
    assert statuses.count(200) == 1 and statuses.count(401) == 7
    assert len(h.authority.provider_calls) == 1


def test_parent_exchange_is_consumed(h):
    root = h.root_token()
    assert h.exchange(root, "reviewer").status_code == 200
    assert h.exchange(root, "reviewer").status_code == 400
