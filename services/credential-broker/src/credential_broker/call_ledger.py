"""Durable one-use state; never stores a provider credential or its wrapping key."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, cast

from .models import BrokerError, Principal, canonical
from .vault import Vault


class CallLedger:
    def __init__(self, vault: Vault):
        self.vault = vault
        with vault._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS call_issuer (id INTEGER PRIMARY KEY, audience TEXT)"
            )
            db.execute("INSERT OR IGNORE INTO call_issuer VALUES (1,?)", (uuid.uuid4().hex,))
            self.audience: str = db.execute(
                "SELECT audience FROM call_issuer WHERE id=1"
            ).fetchone()[0]
            db.execute("""CREATE TABLE IF NOT EXISTS calendar_calls (
                id TEXT PRIMARY KEY, tenant TEXT, subject TEXT, channel TEXT,
                metadata TEXT, aad_hash TEXT, expires REAL, state TEXT, receipt TEXT)""")

    def add(self, metadata: dict[str, Any], aad_hash: str) -> None:
        with self.vault._db() as db:
            db.execute("DELETE FROM calendar_calls WHERE expires < ?", (time.time(),))
            if db.execute("SELECT COUNT(*) FROM calendar_calls").fetchone()[0] >= 1000:
                raise BrokerError(429, "call_capacity_exceeded")
            pending = db.execute(
                "SELECT COUNT(*) FROM calendar_calls WHERE tenant=? AND state='pending'",
                (metadata["tenant"],),
            ).fetchone()[0]
            if pending >= 16:
                raise BrokerError(429, "tenant_call_capacity_exceeded")
            db.execute(
                "INSERT INTO calendar_calls VALUES (?,?,?,?,?,?,?,'pending',NULL)",
                (
                    metadata["grant_id"],
                    metadata["tenant"],
                    metadata["subject"],
                    metadata["channel"],
                    canonical(metadata).decode(),
                    aad_hash,
                    metadata["expires_at"],
                ),
            )
            self.vault._audit(
                db,
                metadata["tenant"],
                metadata["approved_by"],
                metadata["grant_id"],
                "call_approved",
                201,
            )

    def lookup(self, grant_id: str, principal: Principal) -> tuple[dict[str, Any], str]:
        with self.vault._db() as db:
            row = db.execute(
                "SELECT metadata,aad_hash FROM calendar_calls WHERE id=? AND tenant=? AND subject=? AND channel=?",
                (
                    grant_id,
                    principal.tenant,
                    principal.subject,
                    principal.channel,
                ),
            ).fetchone()
        if row is None:
            raise BrokerError(404, "call_unavailable")
        return cast(dict[str, Any], json.loads(row[0])), row[1]

    def consume(self, grant_id: str, aad_hash: str) -> None:
        with self.vault._db() as db:
            row = db.execute(
                "SELECT tenant,subject,expires,state,aad_hash FROM calendar_calls WHERE id=?",
                (grant_id,),
            ).fetchone()
            if row is None or row[3] != "pending" or row[4] != aad_hash or row[2] <= time.time():
                raise BrokerError(409, "call_not_pending")
            db.execute("UPDATE calendar_calls SET state='consumed' WHERE id=?", (grant_id,))
            self.vault._audit(db, row[0], row[1], grant_id, "call_consumed_before_dispatch", 0)

    def finish(self, grant_id: str, receipt: dict[str, Any]) -> None:
        with self.vault._db() as db:
            row = db.execute(
                "SELECT tenant,subject FROM calendar_calls WHERE id=? AND state='consumed'",
                (grant_id,),
            ).fetchone()
            if row is None:
                raise BrokerError(409, "call_not_consumed")
            db.execute(
                "UPDATE calendar_calls SET receipt=? WHERE id=?",
                (canonical(receipt).decode(), grant_id),
            )
            self.vault._audit(db, row[0], row[1], grant_id, "call_credential_destroyed", 0)

    def receipt(self, grant_id: str, principal: Principal) -> dict[str, Any]:
        self.lookup(grant_id, principal)
        with self.vault._db() as db:
            row = db.execute(
                "SELECT receipt FROM calendar_calls WHERE id=?", (grant_id,)
            ).fetchone()
        if row is None or row[0] is None:
            raise BrokerError(409, "receipt_unavailable")
        return cast(dict[str, Any], json.loads(row[0]))

    def revoke(self, grant_id: str, principal: Principal, custody_owner: str) -> None:
        if not principal.admin:
            raise BrokerError(403, "admin_required")
        with self.vault._db() as db:
            row = db.execute(
                "SELECT state,metadata FROM calendar_calls WHERE id=? AND tenant=?",
                (grant_id, principal.tenant),
            ).fetchone()
            if row is None:
                raise BrokerError(404, "call_unavailable")
            if json.loads(row[1])["custody_owner"] != custody_owner:
                raise BrokerError(503, "call_owner_unavailable")
            if row[0] != "pending":
                raise BrokerError(409, "call_not_pending")
            db.execute("UPDATE calendar_calls SET state='revoked' WHERE id=?", (grant_id,))
            self.vault._audit(
                db, principal.tenant, principal.subject, grant_id, "call_revoked", 204
            )
