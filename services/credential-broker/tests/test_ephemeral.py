from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

import credential_broker.ephemeral as ephemeral_module
from credential_broker.ephemeral import EphemeralSecrets
from credential_broker.models import BrokerError, canonical

SECRET = "synthetic-calendar-access-token"
AAD = canonical(
    {
        "schema": "one-off-calendar-v1",
        "actor": "alice",
        "connection": "google-calendar",
        "calendar": "primary",
        "operation": "events.insert",
        "arguments": {"summary": "Appointment"},
        "session": "session-a",
        "channel": "channel-a",
    }
)


def custody(*, capacity: int = 64) -> EphemeralSecrets:
    return EphemeralSecrets(max_pending=capacity, clock=lambda: 100.0)


def test_success_consumes_ciphertext_and_wipes_owned_key_before_provider_use() -> None:
    vault = custody()
    vault.seal("grant", SECRET, AAD, 200)
    entry = vault._entries["grant"]
    owned_key = entry.key
    assert len(owned_key) == 32 and any(owned_key)
    ciphertext = entry.ciphertext
    assert SECRET.encode() not in ciphertext
    with vault.take("grant", AAD) as revealed:
        assert revealed == SECRET
        assert vault.active_count == 0
        assert owned_key == bytearray(32)
        assert entry.ciphertext == b""
        assert entry.nonce == b""
    with pytest.raises(BrokerError, match="grant_unavailable") as replay:
        with vault.take("grant", AAD):
            pytest.fail("replay must not reveal a credential")
    assert replay.value.status == 404


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor", "mallory"),
        ("connection", "other-connection"),
        ("calendar", "someone-else"),
        ("operation", "events.delete"),
        ("arguments", {"summary": "Different appointment"}),
        ("session", "session-b"),
        ("channel", "channel-b"),
    ],
)
def test_each_contract_change_fails_and_destroys_custody(field: str, value: object) -> None:
    import json

    vault = custody()
    vault.seal("grant", SECRET, AAD, 200)
    entry = vault._entries["grant"]
    changed = json.loads(AAD)
    changed[field] = value
    with pytest.raises(BrokerError, match="credential_binding_mismatch") as failure:
        with vault.take("grant", canonical(changed)):
            pytest.fail("altered AAD must not decrypt")
    assert failure.value.status == 409
    assert vault.active_count == 0
    assert entry.key == bytearray(32)
    assert entry.ciphertext == b""
    with pytest.raises(BrokerError, match="grant_unavailable"):
        with vault.take("grant", AAD):
            pytest.fail("an AAD failure must consume the grant")


@pytest.mark.parametrize("failure", [RuntimeError("provider failed"), asyncio.CancelledError()])
def test_exception_and_cancellation_leave_no_custody(failure: BaseException) -> None:
    vault = custody()
    vault.seal("grant", SECRET, AAD, 200)
    key = vault._entries["grant"].key
    with pytest.raises(type(failure)):
        with vault.take("grant", AAD):
            raise failure
    assert vault.active_count == 0
    assert key == bytearray(32)


def test_task_cancellation_during_provider_await_cannot_restore_custody() -> None:
    vault = custody()
    vault.seal("grant", SECRET, AAD, 200)
    key = vault._entries["grant"].key

    async def scenario() -> None:
        entered = asyncio.Event()

        async def provider_call() -> None:
            with vault.take("grant", AAD) as revealed:
                assert revealed == SECRET
                entered.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(provider_call())
        await asyncio.wait_for(entered.wait(), timeout=1)
        assert vault.active_count == 0
        assert key == bytearray(32)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(BrokerError, match="grant_unavailable"):
            with vault.take("grant", AAD):
                pytest.fail("cancellation must not permit a retry")

    asyncio.run(scenario())


def test_ciphertext_corruption_fails_closed_and_destroys_key() -> None:
    vault = custody()
    vault.seal("grant", SECRET, AAD, 200)
    entry = vault._entries["grant"]
    entry.ciphertext = bytes([entry.ciphertext[0] ^ 1]) + entry.ciphertext[1:]
    with pytest.raises(BrokerError, match="credential_binding_mismatch"):
        with vault.take("grant", AAD):
            pytest.fail("corrupted ciphertext must not reveal plaintext")
    assert vault.active_count == 0
    assert entry.key == bytearray(32)
    assert entry.ciphertext == b""


def test_encryption_failure_destroys_unpublished_key(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_keys: list[bytearray] = []

    class FailingCipher:
        def __init__(self, key: bytearray):
            captured_keys.append(key)

        def encrypt(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
            raise RuntimeError("synthetic cipher failure")

    monkeypatch.setattr(ephemeral_module, "AESGCM", FailingCipher)
    vault = custody()
    with pytest.raises(RuntimeError, match="synthetic cipher failure"):
        vault.seal("grant", SECRET, AAD, 200)
    assert vault.active_count == 0
    assert captured_keys == [bytearray(32)]


def test_concurrent_take_has_exactly_one_winner() -> None:
    vault = custody()
    vault.seal("grant", SECRET, AAD, 200)
    key = vault._entries["grant"].key
    barrier = threading.Barrier(8)

    def attempt() -> bool:
        barrier.wait(timeout=5)
        try:
            with vault.take("grant", AAD) as revealed:
                assert revealed == SECRET
                return True
        except BrokerError as exc:
            assert exc.code == "grant_unavailable"
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: attempt(), range(8)))
    assert sum(results) == 1
    assert vault.active_count == 0
    assert key == bytearray(32)


def test_expiry_prunes_and_destroys_key_at_the_exact_boundary() -> None:
    now = [100.0]
    vault = EphemeralSecrets(clock=lambda: now[0])
    vault.seal("grant", SECRET, AAD, 101)
    entry = vault._entries["grant"]
    now[0] = 101.0
    with pytest.raises(BrokerError, match="grant_unavailable"):
        with vault.take("grant", AAD):
            pytest.fail("expired credentials must not decrypt")
    assert entry.key == bytearray(32)
    assert entry.ciphertext == b""
    assert vault.active_count == 0


def test_explicit_expiry_sweep_destroys_all_expired_keys() -> None:
    now = [100.0]
    vault = EphemeralSecrets(clock=lambda: now[0])
    vault.seal("earlier", SECRET, AAD, 101)
    vault.seal("later", SECRET, AAD, 102)
    earlier = vault._entries["earlier"].key
    later = vault._entries["later"].key
    now[0] = 101.0
    vault.prune()
    assert earlier == bytearray(32)
    assert any(later)
    assert vault.active_count == 1
    vault.close()
    assert later == bytearray(32)


def test_capacity_and_duplicate_rejection_preserve_existing_custody() -> None:
    vault = custody(capacity=1)
    vault.seal("grant", SECRET, AAD, 200)
    original_key = vault._entries["grant"].key
    with pytest.raises(BrokerError, match="grant_already_exists") as duplicate:
        vault.seal("grant", "another-synthetic-token", AAD, 200)
    assert duplicate.value.status == 409
    with pytest.raises(BrokerError, match="credential_custody_full") as full:
        vault.seal("other", SECRET, AAD, 200)
    assert full.value.status == 503
    assert vault.active_count == 1
    assert vault._entries["grant"].key is original_key
    with vault.take("grant", AAD) as revealed:
        assert revealed == SECRET


def test_expired_capacity_can_be_reused_with_an_independent_key() -> None:
    now = [100.0]
    vault = EphemeralSecrets(max_pending=1, clock=lambda: now[0])
    vault.seal("first", SECRET, AAD, 101)
    old_key = vault._entries["first"].key
    now[0] = 101.0
    vault.seal("second", SECRET, AAD, 102)
    assert old_key == bytearray(32)
    assert vault.active_count == 1
    assert any(vault._entries["second"].key)


def test_discard_and_close_are_idempotent_and_close_is_permanent() -> None:
    vault = custody()
    vault.seal("first", SECRET, AAD, 200)
    vault.seal("second", SECRET, AAD, 200)
    first_key = vault._entries["first"].key
    second_key = vault._entries["second"].key
    assert first_key != second_key
    vault.discard("first")
    vault.discard("first")
    assert first_key == bytearray(32)
    assert any(second_key)
    vault.close()
    vault.close()
    vault.discard("second")
    assert second_key == bytearray(32)
    assert vault.active_count == 0
    with pytest.raises(BrokerError, match="credential_custody_unavailable") as closed:
        vault.seal("third", SECRET, AAD, 200)
    assert closed.value.status == 503
    with pytest.raises(BrokerError, match="credential_custody_unavailable"):
        with vault.take("second", AAD):
            pytest.fail("closed custody must not reveal credentials")


def test_representations_do_not_include_plaintext_ciphertext_or_key() -> None:
    vault = custody()
    vault.seal("grant", SECRET, AAD, 200)
    entry = vault._entries["grant"]
    representations = repr(vault) + repr(entry)
    assert SECRET not in representations
    assert repr(entry.key) not in representations
    assert repr(entry.ciphertext) not in representations
    assert AAD.decode() not in representations


@pytest.mark.parametrize("expiry", [100, 99, float("nan"), float("inf"), True])
def test_invalid_expiry_never_creates_custody(expiry: float) -> None:
    vault = custody()
    with pytest.raises(BrokerError, match="invalid_expiry"):
        vault.seal("grant", SECRET, AAD, expiry)
    assert vault.active_count == 0


@pytest.mark.parametrize("capacity", [0, 65, -1, True])
def test_capacity_limit_is_bounded(capacity: int) -> None:
    with pytest.raises(ValueError, match="max_pending"):
        EphemeralSecrets(max_pending=capacity)
