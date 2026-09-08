"""Runnable local demonstration: independent service and callback ASGI applications."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, cast

import httpx
from fastapi.testclient import TestClient
from joserfc.jwk import OKPKey

from credential_broker.delegation import statements
from credential_broker.delegation.api import application, callback_application
from credential_broker.delegation.client import Inbox
from credential_broker.delegation.crypto import dpop, envelope, sign, valid, verify
from credential_broker.delegation.execution import Result
from credential_broker.delegation.service import PENDING, Config, ReturnChannel, Service
from credential_broker.delegation.transport import HttpCallbacks

from ._profile import ISSUER, RESOURCE

CALL: dict[str, Any] = {
    "calendar_id": "primary",
    "send_updates": "none",
    "event": {
        "id": "abcde12345",
        "summary": "One approved event",
        "start": {"dateTime": "2026-09-10T17:00:00Z"},
        "end": {"dateTime": "2026-09-10T17:30:00Z"},
    },
}
DETAILS = [
    {
        "type": "urn:schemen:authorization:calendar-event-v1",
        "actions": ["create"],
        "locations": [RESOURCE],
        "call": CALL,
    }
]


class CountedExecutor:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def execute(
        self, request_id: str, actor: str, call: dict[str, Any], *, tenant: str, connection: str
    ) -> Result:
        self.calls.append(call)
        return Result("confirmed", call["event"]["id"])


class BoundHarness:
    def __init__(self, directory: Path):
        self.directory = directory
        self.keys = {
            name: OKPKey.generate_key("Ed25519")
            for name in ("service", "owner", "reviewer", "worker", "outsider")
        }
        self.gate_key = secrets.token_bytes(32)
        self.inbox_key = secrets.token_bytes(32)
        self.url = "https://caller.example/callback"
        self.config = Config(
            ISSUER,
            RESOURCE,
            "alice",
            "google-calendar-v1",
            (self.keys["owner"].thumbprint(),),
            (
                ReturnChannel("worker", self.keys["worker"].thumbprint(), self.url),
                ReturnChannel(
                    "outsider",
                    self.keys["outsider"].thumbprint(),
                    "https://outside.example/callback",
                ),
            ),
        )
        self.inbox = Inbox(
            ISSUER,
            self.keys["service"],
            self.keys["worker"],
            self.url,
            directory / "inbox.db",
            self.inbox_key,
        )
        self.callback_app = callback_application(self.inbox)
        self.callbacks = HttpCallbacks(
            (self.url,), transport=httpx.ASGITransport(app=self.callback_app)
        )
        self.executor = CountedExecutor()
        self.restart()

    def restart(self) -> None:
        self.service = Service(
            self.config, self.keys["service"], self.gate_key, self.directory / "flow.db"
        )
        self.http = TestClient(
            application(self.service, self.executor, self.callbacks), base_url=ISSUER
        )

    def start(self) -> str:
        self.request = statements.request(
            self.keys["worker"],
            ISSUER,
            RESOURCE,
            "worker",
            DETAILS,
            tenant=self.config.tenant,
            connection=self.config.connection,
        )
        response = self.http.post("/requests", json={"statement": self.request})
        assert response.status_code == 200, response.text
        self.ack = response.json()
        pending, _ = verify(self.ack["pending"], PENDING, expected=self.keys["service"])
        self.pending = pending
        self.identifier = self.inbox.expect(self.request, self.ack["pending"])
        return self.identifier

    def approve(self, delegated: bool = True, decision: str = "approve") -> Any:
        owner = self.keys["owner"]
        lookup = sign(
            owner,
            "schemen-review-request+jwt",
            {**envelope(owner, ISSUER + "/reviews"), "request_id": self.identifier},
        )
        response = self.http.post("/reviews", json={"statement": lookup, "chain": []})
        assert response.status_code == 200, response.text
        reviewed, _ = verify(
            response.json()["review"], "schemen-review+jwt", expected=self.keys["service"]
        )
        valid(reviewed, ISSUER, owner.thumbprint())
        assert reviewed["request"] == self.request
        assert reviewed["request_sha256"] == self.pending["request_sha256"]
        chain = []
        signer = self.keys["owner"]
        if delegated:
            signer = self.keys["reviewer"]
            chain = [
                statements.delegate(
                    self.keys["owner"],
                    signer.thumbprint(),
                    ISSUER,
                    self.pending["request_sha256"],
                    ttl=120,
                )
            ]
        self.chain = chain
        self.approval = statements.approve(
            signer,
            ISSUER,
            self.identifier,
            self.pending["request_sha256"],
            chain,
            decision=decision,
        )
        return self.http.post(
            "/approvals",
            json={"request_id": self.identifier, "statement": self.approval, "chain": chain},
        )

    def form(self, key: OKPKey | None = None) -> dict[str, str]:
        _, callback = self.service.callback(self.identifier)
        return statements.exchange_form(
            key or self.keys["worker"], ISSUER, RESOURCE, callback, self.ack["actor_token"], DETAILS
        )

    def redeem(self, form: dict[str, str] | None = None, proof: str | None = None) -> Any:
        return self.http.post(
            "/token",
            data=form or self.form(),
            headers={
                "DPoP": proof or dpop(self.keys["worker"], ISSUER + "/token", self.pending["nonce"])
            },
        )

    def ready(self) -> str:
        self.start()
        response = self.approve()
        assert response.json()["callback_delivered"] is True, response.text
        token = self.redeem()
        assert token.status_code == 200, token.text
        self.token = token.json()["access_token"]
        return cast(str, self.token)

    def execution_proof(self, token: str, nonce: str | None = None) -> str:
        with self.service.store.transaction() as db:
            row = self.service.store.load(db, self.identifier)
        return dpop(self.keys["worker"], RESOURCE, nonce or row["execution_nonce"], token)

    def execute(self, token: str, call: Any = None, proof: str | None = None) -> Any:
        return self.http.post(
            RESOURCE,
            json={"call": CALL if call is None else call},
            headers={
                "Authorization": "DPoP " + token,
                "DPoP": proof or self.execution_proof(token),
            },
        )


def main() -> None:
    import argparse
    import copy
    import json
    import os
    import tempfile

    parser = argparse.ArgumentParser(
        description="Demonstrate signed delegation and callback binding"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="schemen-bound-flow-") as directory:
        flow = BoundHarness(Path(directory))
        trace: list[dict[str, Any]] = []

        def record(stage: str, status: int) -> None:
            trace.append(
                {
                    "stage": stage,
                    "http_status": status,
                    "provider_effects": len(flow.executor.calls),
                }
            )

        flow.start()
        record("Signed request accepted; paused for approval", 200)
        decision = flow.approve()
        assert decision.json()["callback_delivered"] is True
        record(
            "Owner delegated approval; reviewer signed; caller verified callback",
            decision.status_code,
        )
        response = flow.redeem()
        assert response.status_code == 200
        token = response.json()["access_token"]
        record("Bound caller authenticated and redeemed using DPoP", response.status_code)
        changed = copy.deepcopy(CALL)
        changed["event"]["summary"] = "Unapproved substitution"
        denied = flow.execute(token, call=changed)
        assert denied.status_code == 403
        record("Changed operation rejected by Gate", denied.status_code)
        flow.restart()
        executed = flow.execute(token)
        assert executed.status_code == 200
        receipt = flow.inbox.result(executed.json()["receipt"], flow.identifier)
        assert receipt["outcome"] == "confirmed"
        record(
            "Restarted service executes exact operation; caller verifies signed result",
            executed.status_code,
        )
        flow.restart()
        replay = flow.execute(token)
        assert replay.status_code == 403 and len(flow.executor.calls) == 1
        record("Repeat refused after another restart", replay.status_code)
        output = (
            json.dumps(
                {
                    "status": "PASS",
                    "algorithm": "Ed25519",
                    "scope": "ASGI HTTP demonstration with synthetic keys and counted executor; no Google call",
                    "request_sha256": flow.pending["request_sha256"],
                    "trace": trace,
                },
                indent=2,
            )
            + "\n"
        )
    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(output)
    print(output, end="")


if __name__ == "__main__":
    main()
