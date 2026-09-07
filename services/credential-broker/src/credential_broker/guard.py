"""Authentication and admission cover the complete ASGI response lifetime."""

from __future__ import annotations

import asyncio
import re

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .limits import Limits
from .models import BrokerError, Principal, token_hash

RESPONSE_TIMEOUT = 10.0


def authenticate(request: Request, identities: dict[str, Principal]) -> Principal:
    headers = request.headers.getlist("authorization")
    if len(headers) != 1 or not headers[0].startswith("Bearer "):
        raise BrokerError(401, "unauthorized")
    token = headers[0][7:]
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        raise BrokerError(401, "unauthorized")
    principal = identities.get(token_hash(token))
    if principal is None:
        raise BrokerError(401, "unauthorized")
    return principal


class RequestGuard:
    def __init__(self, app: ASGIApp, identities: dict[str, Principal], limits: Limits):
        self.app, self.identities, self.limits = app, dict(identities), limits

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False
        deadline: float | None = None

        async def bounded_send(message: Message) -> None:
            nonlocal started, deadline
            if deadline is None:
                deadline = asyncio.get_running_loop().time() + RESPONSE_TIMEOUT
            if message["type"] == "http.response.start":
                started = True
                headers = MutableHeaders(scope=message)
                headers["Cache-Control"] = "no-store"
                headers["X-Content-Type-Options"] = "nosniff"
            async with asyncio.timeout_at(deadline):
                await send(message)

        try:
            # Compare the same ASGI path used by routing. Every HTTP path is
            # protected except the exact public health operation.
            if scope["path"] == "/healthz" and scope["method"] == "GET":
                await self.app(scope, receive, bounded_send)
            else:
                principal = authenticate(Request(scope), self.identities)
                scope.setdefault("state", {})["principal"] = principal
                with self.limits.admit(principal):
                    await self.app(scope, receive, bounded_send)
        except Exception as exc:
            if started:
                # A response cannot be replaced after headers. Abort without
                # exposing provider or transport exception strings to logs.
                raise RuntimeError("broker response aborted") from None
            status, code = (
                (exc.status, exc.code) if isinstance(exc, BrokerError) else (500, "internal_error")
            )
            await JSONResponse({"error": code}, status_code=status)(scope, receive, bounded_send)
