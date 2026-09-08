"""Falsify one-call cryptographic binding independently of HTTP and durable replay."""

from __future__ import annotations

import copy
import json
import time
from typing import Any

import pytest

from credential_broker import call_gate
from credential_broker.models import BrokerError

KEY = b"a" * 32
CONTRACT: dict[str, Any] = {
    "tenant": "alice",
    "subject": "calendar-agent",
    "channel": "tool-call-17",
    "grant_id": "grant-1",
    "broker_audience": "calendar-broker",
    "connection_id": "calendar",
    "connection_revision": "revision-1",
    "provider": "google-calendar",
    "provider_fingerprint": "a" * 64,
    "request": {
        "origin": "https://www.googleapis.com",
        "method": "POST",
        "path": "/calendar/v3/calendars/primary/events",
        "query": {"sendUpdates": "none"},
        "json": {
            "summary": "Review",
            "start": {"dateTime": "2026-09-10T10:00:00Z"},
            "end": {"dateTime": "2026-09-10T10:30:00Z"},
            "attendees": [{"email": "guest@example.com"}],
        },
    },
    "response_policy": "calendar-event-id-only",
}


@pytest.fixture
def installed_gate() -> None:
    pytest.importorskip("schemen_gate")


def _leaves(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    if isinstance(value, dict):
        return [path for key, item in value.items() for path in _leaves(item, (*prefix, key))]
    if isinstance(value, list):
        return [path for key, item in enumerate(value) for path in _leaves(item, (*prefix, key))]
    return [prefix]


def _changed(value: dict[str, Any], path: tuple[Any, ...]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] += "-changed"
    return result


def _denied(callback: Any) -> None:
    with pytest.raises(BrokerError) as error:
        callback()
    assert (error.value.status, error.value.code) == (403, "call_gate_invalid")
    assert error.value.__suppress_context__


def test_exact_calendar_contract_round_trips_without_event_content(installed_gate):
    expiry = time.time() + 60
    token = call_gate.issue(KEY, CONTRACT, expiry)
    call_gate.authenticate(KEY, json.loads(json.dumps(token)), CONTRACT, expiry)
    # AAD commits to full event bytes without copying those bytes into the token.
    assert "guest@example.com" not in json.dumps(token)
    assert token["aad"]["child_symbols"] == []
    assert token["aad"]["delegation_depth_remaining"] == 0
    # Authentication is deliberately stateless; the vault must enforce one use.
    call_gate.authenticate(KEY, token, CONTRACT, expiry)


@pytest.mark.parametrize("path", _leaves(CONTRACT), ids=lambda p: ".".join(map(str, p)))
def test_every_actual_contract_field_is_authenticated(installed_gate, path):
    expiry = time.time() + 60
    token = call_gate.issue(KEY, CONTRACT, expiry)
    _denied(lambda: call_gate.authenticate(KEY, token, _changed(CONTRACT, path), expiry))


def test_added_or_removed_contract_fields_are_authenticated(installed_gate):
    expiry = time.time() + 60
    token = call_gate.issue(KEY, CONTRACT, expiry)
    _denied(lambda: call_gate.authenticate(KEY, token, {**CONTRACT, "extra": True}, expiry))
    reduced = {key: value for key, value in CONTRACT.items() if key != "channel"}
    _denied(lambda: call_gate.authenticate(KEY, token, reduced, expiry))


def test_json_order_is_canonical_but_types_remain_distinct(installed_gate):
    expiry = time.time() + 60
    contract = {**CONTRACT, "number": 1}
    token = call_gate.issue(KEY, contract, expiry)
    call_gate.authenticate(KEY, token, dict(reversed(list(contract.items()))), expiry)
    for number in (True, 1.0, "1"):
        changed = {**contract, "number": number}
        _denied(lambda changed=changed: call_gate.authenticate(KEY, token, changed, expiry))


@pytest.mark.parametrize(
    "field", ["schema", "issuer_context", "nonce", "ciphertext", "expires_epoch"]
)
def test_token_metadata_and_ciphertext_tampering_fail_closed(installed_gate, field):
    expiry = time.time() + 60
    token = call_gate.issue(KEY, CONTRACT, expiry)
    if field == "expires_epoch":
        token[field] += 1
    elif field in {"nonce", "ciphertext"}:
        token[field] = ("1" if token[field][0] == "0" else "0") + token[field][1:]
    else:
        token[field] += "00"
    _denied(lambda: call_gate.authenticate(KEY, token, CONTRACT, expiry))


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("package", "other-package"),
        ("version", "1.0.99"),
        ("source_repository", "https://github.com/example/other"),
        ("source_commit", "b" * 40),
    ],
)
def test_gate_release_is_bound(installed_gate, field, replacement):
    expiry = time.time() + 60
    token = call_gate.issue(KEY, CONTRACT, expiry)
    token["aad"]["gate_release"][field] = replacement
    _denied(lambda: call_gate.authenticate(KEY, token, CONTRACT, expiry))


def test_gate_aad_and_unknown_token_fields_are_bound(installed_gate):
    expiry = time.time() + 60
    token = call_gate.issue(KEY, CONTRACT, expiry)
    changed = copy.deepcopy(token)
    changed["aad"]["arguments_sha256"] = "0" * 64
    _denied(lambda: call_gate.authenticate(KEY, changed, CONTRACT, expiry))
    _denied(lambda: call_gate.authenticate(KEY, {**token, "unrecognized": True}, CONTRACT, expiry))


@pytest.mark.parametrize("key", [b"b" * 32, b"a" * 31, "a" * 32])
def test_wrong_or_malformed_authority_keys_fail_closed(installed_gate, key):
    expiry = time.time() + 60
    token = call_gate.issue(KEY, CONTRACT, expiry)
    _denied(lambda: call_gate.authenticate(key, token, CONTRACT, expiry))


def test_independent_tenant_key_derivation_blocks_transplanted_aad(installed_gate):
    expiry = time.time() + 60
    alice = call_gate.issue(KEY, CONTRACT, expiry)
    bob_contract = {**CONTRACT, "tenant": "bob"}
    bob = call_gate.issue(KEY, bob_contract, expiry)
    alice["aad"] = bob["aad"]
    _denied(lambda: call_gate.authenticate(KEY, alice, bob_contract, expiry))


@pytest.mark.parametrize("expiry", [True, None, "3000000000", 0, -1, float("nan"), float("inf")])
def test_invalid_expiry_fails_closed(installed_gate, expiry):
    _denied(lambda: call_gate.issue(KEY, CONTRACT, expiry))


def test_fractional_expiry_does_not_gain_a_rounding_grace_period(installed_gate, monkeypatch):
    monkeypatch.setattr(call_gate.time, "time", lambda: 2_000_000_000.0)
    expiry = 2_000_000_000.25
    token = call_gate.issue(KEY, CONTRACT, expiry)
    call_gate.authenticate(KEY, token, CONTRACT, expiry)
    _denied(lambda: call_gate.authenticate(KEY, token, CONTRACT, expiry + 0.01))
    monkeypatch.setattr(call_gate.time, "time", lambda: expiry)
    _denied(lambda: call_gate.authenticate(KEY, token, CONTRACT, expiry))


@pytest.mark.parametrize(
    "contract",
    [
        {},
        {"tenant": ""},
        {"tenant": True},
        {"tenant": "a\x00b"},
        {"tenant": "alice", "request": {1: "invalid"}},
        {"tenant": "alice", "request": ("tuple",)},
        {"tenant": "alice", "request": float("nan")},
    ],
)
def test_noncanonical_contracts_are_refused(installed_gate, contract):
    _denied(lambda: call_gate.issue(KEY, contract, time.time() + 60))


def test_missing_optional_gate_dependency_fails_closed(monkeypatch):
    def missing(name):
        raise ImportError("synthetic missing optional dependency")

    monkeypatch.setattr(call_gate.importlib, "import_module", missing)
    for operation in (
        lambda: call_gate.issue(KEY, CONTRACT, time.time() + 60),
        lambda: call_gate.authenticate(KEY, {}, CONTRACT, time.time() + 60),
    ):
        with pytest.raises(BrokerError) as error:
            operation()
        assert (error.value.status, error.value.code) == (503, "call_gate_unavailable")
