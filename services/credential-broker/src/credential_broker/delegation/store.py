"""Owner-only SQLite state; atomic transitions and replay survive service restart."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from credential_broker.models import canonical

from ._profile import Denied, loads, require


class Store:
    def __init__(self, path: Path, identity: str, encryption_key: bytes) -> None:
        parent = path.parent.stat()
        require(
            not path.parent.is_symlink()
            and stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == os.getuid()
            and parent.st_mode & 0o077 == 0
        )
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0
            )
        finally:
            os.close(fd)
        self.path = path
        self.cipher = AESGCM(encryption_key)
        identity += ":" + hashlib.sha256(encryption_key).hexdigest()
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS identity (value TEXT PRIMARY KEY)")
            old = db.execute("SELECT value FROM identity").fetchone()
            require(old is None or old[0] == identity, "configuration_changed")
            if old is None:
                db.execute("INSERT INTO identity VALUES (?)", (identity,))
            db.execute(
                "CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, data TEXT NOT NULL)"
            )
            db.execute("CREATE TABLE IF NOT EXISTS replay (key TEXT PRIMARY KEY, expires INTEGER)")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def replay(db: sqlite3.Connection, namespace: str, identifier: str, expiry: int) -> None:
        db.execute("DELETE FROM replay WHERE expires < ?", (int(time.time()),))
        require(db.execute("SELECT COUNT(*) FROM replay").fetchone()[0] < 10000, "capacity")
        try:
            db.execute("INSERT INTO replay VALUES (?, ?)", (namespace + ":" + identifier, expiry))
        except sqlite3.IntegrityError:
            raise Denied("replayed_proof") from None

    def load(self, db: sqlite3.Connection, identifier: object) -> dict[str, Any]:
        require(type(identifier) is str and 16 <= len(identifier) <= 128)
        identifier = cast(str, identifier)
        row = db.execute("SELECT data FROM requests WHERE id=?", (identifier,)).fetchone()
        require(row is not None, "unknown_request")
        try:
            result: dict[str, Any] = loads(
                self.cipher.decrypt(row[0][:12], row[0][12:], identifier.encode())
            )
        except Exception:
            raise Denied("state_authentication_failed") from None
        return result

    def encoded(self, row: dict[str, Any]) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.cipher.encrypt(nonce, canonical(row), row["id"].encode())

    def save(self, db: sqlite3.Connection, row: dict[str, Any]) -> None:
        db.execute("UPDATE requests SET data=? WHERE id=?", (self.encoded(row), row["id"]))

    def add(self, db: sqlite3.Connection, row: dict[str, Any]) -> None:
        # No implicit eviction of evidence or live grants; operator retention is separate.
        require(db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] < 1000, "capacity")
        db.execute("INSERT INTO requests VALUES (?, ?)", (row["id"], self.encoded(row)))
