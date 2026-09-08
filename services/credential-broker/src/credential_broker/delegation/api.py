"""Runnable HTTP adapters. Application-specific approval endpoints are not claimed as CIBA."""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qsl

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from credential_broker.models import BrokerError

from ._profile import Denied, loads, require
from .client import Inbox
from .crypto import valid, verify
from .execution import Executor, NonceRequired, execute
from .redeem import redeem
from .review import review
from .service import Service
from .transport import Callbacks


async def body(request: Request, content_type: str) -> bytes:
    require(len(request.headers.getlist("content-type")) == 1, "invalid_request")
    require(
        request.headers["content-type"].split(";")[0].strip() == content_type, "invalid_request"
    )
    data = bytearray()
    try:
        async with asyncio.timeout(5):
            async for part in request.stream():
                require(len(data) + len(part) <= 65536, "invalid_request")
                data.extend(part)
    except TimeoutError:
        raise Denied("request_timeout") from None
    return bytes(data)


def application(service: Service, executor: Executor, callbacks: Callbacks) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    @app.exception_handler(Denied)
    async def denied(request: Request, exc: Denied) -> JSONResponse:
        token_endpoint = request.url.path == "/token"
        code = (
            "invalid_request"
            if token_endpoint
            and exc.code
            in {"invalid_grant", "invalid_signature", "unknown_request", "replayed_proof"}
            else exc.code
        )
        headers = {"Cache-Control": "no-store"}
        status = 400 if token_endpoint else 403
        if isinstance(exc, NonceRequired):
            headers.update(
                {"DPoP-Nonce": exc.nonce, "WWW-Authenticate": 'DPoP error="use_dpop_nonce"'}
            )
            status = 400 if token_endpoint else 401
        return JSONResponse({"error": code}, status_code=status, headers=headers)

    @app.exception_handler(BrokerError)
    async def broker_error(request: Request, exc: BrokerError) -> JSONResponse:
        return JSONResponse(
            {"error": "operation_denied"}, status_code=403, headers={"Cache-Control": "no-store"}
        )

    async def malformed(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            {"error": "invalid_request"}, status_code=400, headers={"Cache-Control": "no-store"}
        )

    for error_type in (ValueError, TypeError, KeyError):
        app.add_exception_handler(error_type, malformed)

    @app.post("/{operation:path}")
    async def operation(request: Request, operation: str) -> Response:
        target = (
            service.config.resource
            if operation == "calendar/execute"
            else service.config.issuer + "/" + operation
        )
        require(str(request.url) == target, "wrong_endpoint")
        if operation == "token":
            pairs = parse_qsl(
                (await body(request, "application/x-www-form-urlencoded")).decode(),
                strict_parsing=True,
                keep_blank_values=True,
            )
            require(len(dict(pairs)) == len(pairs), "invalid_request")
            require(len(request.headers.getlist("dpop")) == 1, "invalid_dpop_proof")
            result = redeem(service, dict(pairs), request.headers["dpop"])
        else:
            data = loads(await body(request, "application/json"))
            require(type(data) is dict, "invalid_request")
            if operation == "requests":
                require(set(data) == {"statement"}, "invalid_request")
                result = service.request(data["statement"])
            elif operation == "reviews":
                require(set(data) == {"statement", "chain"}, "invalid_request")
                result = review(service, data["statement"], data["chain"])
            elif operation in {"approvals", "revocations"}:
                require(set(data) == {"request_id", "statement", "chain"}, "invalid_request")
                action = service.approve if operation == "approvals" else service.revoke
                action(data["request_id"], data["statement"], data["chain"])
                delivered = False
                if operation == "approvals":
                    destination, notification = service.callback(data["request_id"])
                    try:
                        await callbacks.send(destination, notification)
                        delivered = True
                    except Exception:
                        pass  # Committed approval/outbox remains available for authenticated retry.
                result = {"accepted": True, "callback_delivered": delivered}
            elif operation == "calendar/execute":
                require(set(data) == {"call"}, "invalid_request")
                require(
                    len(request.headers.getlist("authorization")) == 1
                    and len(request.headers.getlist("dpop")) == 1,
                    "invalid_dpop_proof",
                )
                auth = request.headers["authorization"]
                require(auth.startswith("DPoP "), "invalid_token")
                result = await execute(
                    service, executor, auth[5:], request.headers["dpop"], data["call"]
                )
            elif operation == "results":
                require(set(data) == {"statement"}, "invalid_request")
                claims, key = verify(data["statement"], "schemen-result-request+jwt")
                valid(claims, key, target)
                with service.store.transaction() as db:
                    row = service.store.load(db, claims.get("request_id"))
                    require(row["caller"] == key and "result" in row)
                    service.store.replay(db, "result:" + key, claims["jti"], claims["exp"])
                    result = {"receipt": row["result"]}
            else:
                raise Denied("unknown_endpoint")
        return JSONResponse(result, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    return app


def callback_application(inbox: Inbox) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    @app.post("/{path:path}")
    async def receive(request: Request, path: str) -> Response:
        try:
            require(str(request.url) == inbox.url)
            data = loads(await body(request, "application/json"))
            require(type(data) is dict and set(data) == {"statement"})
            inbox.receive(data["statement"])
        except (Denied, KeyError, ValueError, TypeError):
            return JSONResponse({"error": "invalid_callback"}, status_code=403)
        return Response(status_code=204)

    return app
