"""Bounded, single-use credential custody that never persists its encryption keys.

Each grant owns an independently random DEK. The caller supplies the complete,
canonical authorization contract as AEAD associated data. A take consumes the
entry before decryption; even a binding failure cannot leave a reusable grant.

The erasure claim is deliberately narrow: owned mutable DEK buffers are zeroed
and the custody entry is removed. Python strings, cryptography's native buffers,
provider copies, swap, and process snapshots are outside that guarantee.
"""

from __future__ import annotations

import math
import os
import re
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import BrokerError, identifier


@dataclass(repr=False)
class _SealedSecret:
    key: bytearray = field(repr=False)
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    expires_at: float

    def destroy(self) -> None:
        self.key[:] = b"\x00" * len(self.key)
        self.nonce = b""
        self.ciphertext = b""


class EphemeralSecrets:
    """Process-local one-shot custody with at most 64 pending credentials.

    Expiry is checked under the same lock as admission and consumption. Expired
    entries are destroyed on every operation or explicit ``prune()`` call. A
    caller wanting prompt idle expiry must call ``prune()`` periodically.
    ``close()`` destroys pending custody and permanently rejects new work.
    """

    def __init__(self, *, max_pending: int = 64, clock: Callable[[], float] = time.time) -> None:
        if type(max_pending) is not int or not 1 <= max_pending <= 64:
            raise ValueError("max_pending must be between 1 and 64")
        self._max_pending = max_pending
        self._clock = clock
        self._entries: dict[str, _SealedSecret] = {}
        self._lock = threading.Lock()
        self._closed = False

    @staticmethod
    def _validate_aad(aad: bytes) -> None:
        if not isinstance(aad, bytes) or not 1 <= len(aad) <= 65536:
            raise BrokerError(400, "invalid_grant_binding")

    def _require_open(self) -> None:
        if self._closed:
            raise BrokerError(503, "credential_custody_unavailable")

    def _prune_locked(self, now: float) -> None:
        for grant_id in tuple(self._entries):
            if self._entries[grant_id].expires_at <= now:
                self._entries.pop(grant_id).destroy()

    def prune(self) -> None:
        with self._lock:
            self._prune_locked(self._clock())

    @property
    def active_count(self) -> int:
        with self._lock:
            self._prune_locked(self._clock())
            return len(self._entries)

    def seal(self, grant_id: str, secret: str, aad: bytes, expires_at: float) -> None:
        identifier(grant_id)
        self._validate_aad(aad)
        if not isinstance(secret, str) or not re.fullmatch(r"[\x21-\x7e]{16,8192}", secret):
            raise BrokerError(400, "invalid_credential")
        if type(expires_at) not in {int, float} or not math.isfinite(expires_at):
            raise BrokerError(400, "invalid_expiry")
        with self._lock:
            self._require_open()
            now = self._clock()
            self._prune_locked(now)
            if expires_at <= now:
                raise BrokerError(400, "invalid_expiry")
            if grant_id in self._entries:
                raise BrokerError(409, "grant_already_exists")
            if len(self._entries) >= self._max_pending:
                raise BrokerError(503, "credential_custody_full")
            entry = _SealedSecret(bytearray(os.urandom(32)), b"", b"", expires_at)
            try:
                entry.nonce = os.urandom(12)
                entry.ciphertext = AESGCM(entry.key).encrypt(entry.nonce, secret.encode(), aad)
                self._entries[grant_id] = entry
            except BaseException:
                entry.destroy()
                raise

    @contextmanager
    def take(self, grant_id: str, aad: bytes) -> Iterator[str]:
        identifier(grant_id)
        self._validate_aad(aad)
        with self._lock:
            self._require_open()
            self._prune_locked(self._clock())
            entry = self._entries.pop(grant_id, None)
            if entry is None:
                raise BrokerError(404, "grant_unavailable")
            try:
                try:
                    secret = AESGCM(entry.key).decrypt(entry.nonce, entry.ciphertext, aad).decode()
                except (InvalidTag, ValueError, UnicodeError) as exc:
                    raise BrokerError(409, "credential_binding_mismatch") from exc
            finally:
                # No DEK remains in custody while provider I/O is in flight.
                entry.destroy()
        try:
            yield secret
        finally:
            # Release our plaintext reference. This cannot wipe immutable copies.
            del secret

    def discard(self, grant_id: str) -> None:
        identifier(grant_id)
        with self._lock:
            self._prune_locked(self._clock())
            entry = self._entries.pop(grant_id, None)
            if entry is not None:
                entry.destroy()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for entry in self._entries.values():
                entry.destroy()
            self._entries.clear()
