from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import BrokerError, Connection, canonical


class KeyProvider(Protocol):
    def key(self) -> bytes: ...


class FileKeyProvider:
    def __init__(self, path: Path):
        self.path = path

    def key(self) -> bytes:
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                raise ValueError("key file must be owner-only and owned by this user")
            value = handle.read(33)
        if len(value) != 32:
            raise ValueError("key must contain exactly 32 random bytes")
        return value


class Vault:
    def __init__(self, path: Path, keys: KeyProvider):
        self.path, self.keys = path, keys
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError("database directory must be owner-only and owned by this user")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        os.close(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError("database must be owner-only and owned by this user")
        self._cipher = self._cipher_for(self.keys)
        with self._db(verify=False) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS connections (tenant TEXT, id TEXT, nonce BLOB, ciphertext BLOB, PRIMARY KEY(tenant,id))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS audit (at TEXT DEFAULT CURRENT_TIMESTAMP, tenant TEXT, subject TEXT, connection TEXT, event TEXT, status INTEGER)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS key_check (id INTEGER PRIMARY KEY CHECK(id=1), nonce BLOB, ciphertext BLOB)"
            )
            if db.execute("SELECT 1 FROM key_check").fetchone() is None:
                # One-time migration: never bless a new key over unreadable existing data.
                for tenant, name, nonce, ciphertext in db.execute("SELECT * FROM connections"):
                    self._decrypt(nonce, ciphertext, self._aad(tenant, name))
                self._write_key_check(db, self._cipher)
            self._verify_key(db)

    @staticmethod
    def _cipher_for(keys: KeyProvider) -> AESGCM:
        material = keys.key()
        if not isinstance(material, bytes) or len(material) != 32:
            raise ValueError("key provider must return 32 bytes for AES-256")
        return AESGCM(material)

    @staticmethod
    def _write_key_check(db: sqlite3.Connection, cipher: AESGCM) -> None:
        nonce = os.urandom(12)
        encrypted = cipher.encrypt(nonce, b"credential-broker-key-v1", b"key-check-v1")
        db.execute("INSERT OR REPLACE INTO key_check VALUES (1,?,?)", (nonce, encrypted))

    def _decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            return self._cipher.decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError, TypeError) as exc:
            raise BrokerError(503, "credential_unavailable") from exc

    def _verify_key(self, db: sqlite3.Connection) -> None:
        row = db.execute("SELECT nonce,ciphertext FROM key_check WHERE id=1").fetchone()
        if (
            row is None
            or self._decrypt(row[0], row[1], b"key-check-v1") != b"credential-broker-key-v1"
        ):
            raise BrokerError(503, "credential_unavailable")

    @contextmanager
    def _db(self, *, verify: bool = True) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                if verify:
                    self._verify_key(db)
                yield db
        finally:
            db.close()

    @staticmethod
    def _aad(tenant: str, connection_id: str) -> bytes:
        return canonical({"schema": "credential-broker-v1", "tenant": tenant, "id": connection_id})

    def put(
        self, tenant: str, connection_id: str, connection: Connection, subject: str = "system"
    ) -> None:
        nonce = os.urandom(12)
        encrypted = self._cipher.encrypt(
            nonce, canonical(asdict(connection)), self._aad(tenant, connection_id)
        )
        with self._db() as db:
            exists = db.execute(
                "SELECT 1 FROM connections WHERE tenant=? AND id=?", (tenant, connection_id)
            ).fetchone()
            if (
                not exists
                and db.execute(
                    "SELECT COUNT(*) FROM connections WHERE tenant=?", (tenant,)
                ).fetchone()[0]
                >= 1000
            ):
                raise BrokerError(409, "connection_quota_exceeded")
            db.execute(
                "INSERT OR REPLACE INTO connections VALUES (?,?,?,?)",
                (tenant, connection_id, nonce, encrypted),
            )
            self._audit(db, tenant, subject, connection_id, "credential_stored", 200)

    def get(self, tenant: str, connection_id: str) -> Connection:
        with self._db() as db:
            row = db.execute(
                "SELECT nonce,ciphertext FROM connections WHERE tenant=? AND id=?",
                (tenant, connection_id),
            ).fetchone()
        if row is None:
            raise BrokerError(404, "connection_unavailable")
        try:
            data = json.loads(self._decrypt(row[0], row[1], self._aad(tenant, connection_id)))
            return Connection(
                data["provider"],
                tuple(data["subjects"]),
                data["secret"],
                data["expires_at"],
                data.get("provider_fingerprint"),
            )
        except (InvalidTag, ValueError, KeyError, TypeError) as exc:
            raise BrokerError(503, "credential_unavailable") from exc

    def delete(self, tenant: str, connection_id: str, subject: str = "system") -> None:
        with self._db() as db:
            db.execute("DELETE FROM connections WHERE tenant=? AND id=?", (tenant, connection_id))
            self._audit(db, tenant, subject, connection_id, "credential_revoked", 204)

    def rekey(self, keys: KeyProvider) -> None:
        """Offline, transactional master-key rotation. Existing old-key processes fail closed."""
        cipher = self._cipher_for(keys)
        with self._db() as db:
            for tenant, name, nonce, ciphertext in db.execute(
                "SELECT * FROM connections"
            ).fetchall():
                aad = self._aad(tenant, name)
                plaintext = self._decrypt(nonce, ciphertext, aad)
                new_nonce = os.urandom(12)
                db.execute(
                    "UPDATE connections SET nonce=?,ciphertext=? WHERE tenant=? AND id=?",
                    (new_nonce, cipher.encrypt(new_nonce, plaintext, aad), tenant, name),
                )
            self._write_key_check(db, cipher)
            self._audit(db, "_system", "operator", "_vault", "master_key_rotated", 200)
        self._cipher = cipher
        self.keys = keys

    @staticmethod
    def _audit(
        db: sqlite3.Connection,
        tenant: str,
        subject: str,
        connection_id: str,
        event: str,
        status: int,
    ) -> None:
        db.execute(
            "INSERT INTO audit(tenant,subject,connection,event,status) VALUES (?,?,?,?,?)",
            (tenant, subject, connection_id, event, status),
        )
        # Bounded local ring; operators export before rollover for long-term retention.
        db.execute("DELETE FROM audit WHERE rowid <= (SELECT MAX(rowid)-100000 FROM audit)")

    def audit(self, tenant: str, subject: str, connection_id: str, event: str, status: int) -> None:
        with self._db() as db:
            self._audit(db, tenant, subject, connection_id, event, status)
