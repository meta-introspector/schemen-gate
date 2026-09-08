"""An authorized approver can retrieve the exact signed proposal before deciding."""

from __future__ import annotations

import time
from typing import Any

from ._profile import require
from .crypto import valid, verify
from .delegation import approver
from .service import Service


def review(service: Service, statement: str, chain: list[str]) -> dict[str, Any]:
    claims, key = verify(statement, "schemen-review-request+jwt")
    valid(claims, key, service.config.issuer + "/reviews")
    require(set(claims) == {"iss", "aud", "iat", "exp", "jti", "request_id"})
    with service.store.transaction() as db:
        row = service.store.load(db, claims["request_id"])
        require(time.time() < row["expires"])
        approver(
            chain,
            signer=key,
            root_keys=service.config.owner_keys,
            request_hash=row["hash"],
            audience=service.config.issuer + "/approvals",
        )
        service.store.replay(db, "review:" + key, claims["jti"], claims["exp"])
        result = service.signed(
            "schemen-review+jwt",
            key,
            min(row["expires"], claims["exp"]),
            {
                "request_id": row["id"],
                "request_sha256": row["hash"],
                "request": row["request"],
                "status": row["status"],
                "callback_url": row["callback_url"],
            },
        )
    return {"review": result}
