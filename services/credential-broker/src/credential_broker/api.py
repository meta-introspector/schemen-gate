from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any, NoReturn

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .broker import Broker
from .limits import Limits
from .models import BrokerError, Connection, Principal, canonical, identifier, token_hash

MAX_REQUEST = 65_536


def strict_object(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value: str) -> NoReturn:
        raise ValueError("nonfinite JSON")

    data = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    if not isinstance(data, dict):
        raise ValueError("object required")
    canonical(data)  # Also reject numeric overflow to infinity (e.g. JSON 1e999).
    return data


def create_app(broker: Broker, identities: dict[str, Principal]) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    identities = dict(identities)
    limits = Limits(list(identities.values()))
    app.state.limits = limits

    def authenticate(request: Request) -> Principal:
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

    async def payload(request: Request) -> dict[str, Any]:
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
            raise BrokerError(415, "json_required")
        raw = bytearray()
        try:
            async with asyncio.timeout(10):
                async for chunk in request.stream():
                    raw.extend(chunk)
                    if len(raw) > MAX_REQUEST:
                        raise BrokerError(413, "request_too_large")
        except TimeoutError as exc:
            raise BrokerError(408, "request_timeout") from exc
        try:
            return strict_object(bytes(raw))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise BrokerError(400, "invalid_json") from exc

    @app.exception_handler(BrokerError)
    async def broker_error(request: Request, exc: BrokerError) -> JSONResponse:
        return JSONResponse(
            {"error": exc.code}, status_code=exc.status, headers={"Cache-Control": "no-store"}
        )

    @app.middleware("http")
    async def safe_failure(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        try:
            if request.url.path.startswith("/v1/"):
                principal = authenticate(request)
                with limits.admit(principal):
                    response = await call_next(request)
            else:
                response = await call_next(request)
        except BrokerError as exc:
            response = JSONResponse({"error": exc.code}, status_code=exc.status)
        except Exception:
            # Do not emit request bodies, credentials, URLs or exception messages.
            response = JSONResponse({"error": "internal_error"}, status_code=500)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.put("/v1/connections/{connection_id}")
    async def put_connection(connection_id: str, request: Request) -> dict[str, object]:
        principal = authenticate(request)
        if not principal.admin:
            raise BrokerError(403, "admin_required")
        identifier(connection_id)
        data = await payload(request)
        if set(data) - {"provider", "subjects", "credential", "expires_at"} or not {
            "provider",
            "subjects",
            "credential",
        } <= set(data):
            raise BrokerError(400, "invalid_connection_fields")
        if not isinstance(data["subjects"], list) or not isinstance(data["provider"], str):
            raise BrokerError(400, "invalid_connection")
        if data["provider"] not in broker.providers:
            raise BrokerError(400, "unknown_provider")
        connection = Connection(
            data["provider"],
            tuple(data["subjects"]),
            data["credential"],
            data.get("expires_at"),
            broker.providers[data["provider"]].fingerprint(),
        )
        await run_in_threadpool(
            broker.vault.put, principal.tenant, connection_id, connection, principal.subject
        )
        return {
            "connection_id": connection_id,
            "provider": connection.provider,
            "subjects": connection.subjects,
        }

    @app.delete("/v1/connections/{connection_id}")
    async def delete_connection(connection_id: str, request: Request) -> Response:
        principal = authenticate(request)
        if not principal.admin:
            raise BrokerError(403, "admin_required")
        identifier(connection_id)
        await run_in_threadpool(
            broker.vault.delete, principal.tenant, connection_id, principal.subject
        )
        return Response(status_code=204)

    @app.post("/v1/connections/{connection_id}/request")
    async def proxy(connection_id: str, request: Request) -> Response:
        principal = authenticate(request)
        identifier(connection_id)
        status = 500
        try:
            data = await payload(request)
            if set(data) - {"method", "path", "query", "json"} or not {"method", "path"} <= set(
                data
            ):
                raise BrokerError(400, "invalid_request_fields")
            if not isinstance(data["method"], str):
                raise BrokerError(400, "invalid_method")
            query = data.get("query", {})
            if not isinstance(query, dict) or any(not isinstance(v, str) for v in query.values()):
                raise BrokerError(400, "invalid_query")
            result = await run_in_threadpool(
                broker.request,
                principal,
                connection_id,
                data["method"],
                data["path"],
                query,
                data.get("json"),
            )
            status = result.status
            return Response(result.body, status_code=result.status, media_type=result.content_type)
        except BrokerError as exc:
            status = exc.status
            raise
        finally:
            await run_in_threadpool(
                broker.vault.audit,
                principal.tenant,
                principal.subject,
                connection_id,
                "request_finished",
                status,
            )

    return app
