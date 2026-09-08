from __future__ import annotations

import base64
import copy
import json
from urllib.parse import urlencode

import pytest
from conftest import CALL, DETAILS
from credential_broker.delegation._profile import ACCESS_TYPE, RESOURCE, TOKEN_URL


def test_exchange_access_token_type_accepted_for_second_hop(h):
    first = h.exchange(h.root_token(), "reviewer").json()["access_token"]
    h.decide("reviewer")
    form = h.form(first, "worker")
    form["subject_token_type"] = ACCESS_TYPE
    second = h.exchange(first, "worker", form=form)
    assert second.status_code == 200
    assert h.execute(second.json()["access_token"]).status_code == 200


def test_original_request_is_frozen_by_value(h):
    original = copy.deepcopy(DETAILS)
    root = h.authority.request(original)
    original[0]["call"]["event"]["summary"] = "Caller changed it"
    assert h.authority.pending[root].authorization_details == DETAILS


@pytest.mark.parametrize("mode", ["duplicate_form", "duplicate_json", "nonfinite", "content_type"])
def test_ambiguous_exchange_input_is_rejected(h, mode):
    root = h.root_token()
    form = h.form(root, "reviewer")
    if mode == "duplicate_json":
        form["authorization_details"] = form["authorization_details"].replace(
            '"type":', '"type":"attacker", "type":', 1
        )
    elif mode == "nonfinite":
        form["authorization_details"] = "[NaN]"
    encoded = urlencode(form)
    if mode == "duplicate_form":
        encoded += "&resource=https%3A%2F%2Fevil.example"
    secret = h.authority.principals["reviewer"].client_secret
    result = h.http.post(
        TOKEN_URL,
        content=encoded,
        headers={
            "Authorization": "Basic " + base64.b64encode(f"reviewer:{secret}".encode()).decode(),
            "DPoP": h.keys["reviewer"].proof(TOKEN_URL, h.authority.nonces["token"]),
            "Content-Type": "application/json"
            if mode == "content_type"
            else "application/x-www-form-urlencoded",
        },
    )
    assert result.status_code == 400
    assert h.authority.provider_calls == []


def test_proof_is_checked_against_actual_http_host(h):
    token = h.ready()
    proof = h.keys["worker"].proof(RESOURCE, h.authority.nonces["resource"], token)
    result = h.http.post(
        "https://other.example/calendar/execute",
        json={"call": CALL},
        headers={"Authorization": f"DPoP {token}", "DPoP": proof},
    )
    assert result.json()["error"] == "invalid_dpop_proof"
    assert h.authority.provider_calls == []


def test_proof_for_a_different_access_token_denied(h):
    token = h.ready()
    proof = h.keys["worker"].proof(RESOURCE, h.authority.nonces["resource"], "another-token")
    assert h.execute(token, proof=proof).json()["error"] == "invalid_dpop_proof"
    assert h.authority.provider_calls == []


def test_duplicate_json_in_jwt_header_rejected(h):
    token = h.ready()
    proof = h.keys["worker"].proof(RESOURCE, h.authority.nonces["resource"], token)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    raw = json.dumps({"typ": "dpop+jwt", "alg": "ES256", "jwk": h.keys["worker"].public})
    raw = raw.replace('"alg":', '"alg":"none", "alg":', 1)
    encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    unsigned = encoded + "." + proof.split(".")[1]
    r, s = decode_dss_signature(
        h.keys["worker"].key.sign(unsigned.encode(), ec.ECDSA(hashes.SHA256()))
    )
    signature = (
        base64.urlsafe_b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode().rstrip("=")
    )
    assert h.execute(token, proof=unsigned + "." + signature).status_code == 401
    assert h.authority.provider_calls == []


def test_two_issued_descendants_share_one_root_action_budget(h):
    first = h.ready()
    root = h.authority.root_token(h.root)
    reviewer = h.exchange(root, "reviewer").json()["access_token"]
    second = h.exchange(reviewer, "worker").json()["access_token"]
    assert h.execute(first).status_code == 200
    assert h.execute(second).status_code == 401
    assert len(h.authority.provider_calls) == 1
