from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .broker import Broker
from .calendar_api import register_calendar_routes
from .calendar_calls import CalendarCallService
from .guard import RequestGuard
from .json_codec import strict_object
from .limits import Limits
from .models import BrokerError, Connection, Principal, identifier

MAX_REQUEST = 65_536


def create_app(broker: Broker, identities: dict[str, Principal]) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async def cleanup() -> None:
            while True:
                await asyncio.sleep(1)
                app.state.calendar_calls.secrets.prune()

        task = asyncio.create_task(cleanup())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            app.state.calendar_calls.secrets.close()

    app = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False, lifespan=lifespan
    )
    app.state.calendar_calls = CalendarCallService(broker)
    identities = dict(identities)
    limits = Limits(list(identities.values()))
    app.state.limits = limits

    app.add_middleware(RequestGuard, identities=identities, limits=limits)

    async def payload(request: Request) -> dict[str, Any]:
        types = request.headers.getlist("content-type")
        if len(types) != 1 or types[0].split(";", 1)[0].lower() != "application/json":
            raise BrokerError(415, "json_required")
        if request.headers.getlist("content-encoding"):
            raise BrokerError(415, "request_encoding_blocked")
        raw = bytearray()
        try:
            async with asyncio.timeout(10):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > MAX_REQUEST:
                        raise BrokerError(413, "request_too_large")
                    raw.extend(chunk)
        except TimeoutError as exc:
            raise BrokerError(408, "request_timeout") from exc
        try:
            return strict_object(bytes(raw))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise BrokerError(400, "invalid_json") from exc

    register_calendar_routes(app, payload, identities)

    @app.exception_handler(BrokerError)
    async def broker_error(request: Request, exc: BrokerError) -> JSONResponse:
        return JSONResponse(
            {"error": exc.code}, status_code=exc.status, headers={"Cache-Control": "no-store"}
        )

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.put("/v1/connections/{connection_id}")
    async def put_connection(connection_id: str, request: Request) -> dict[str, object]:
        principal = cast(Principal, request.state.principal)
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
        principal = cast(Principal, request.state.principal)
        if not principal.admin:
            raise BrokerError(403, "admin_required")
        identifier(connection_id)
        await run_in_threadpool(
            broker.vault.delete, principal.tenant, connection_id, principal.subject
        )
        return Response(status_code=204)

    @app.post("/v1/connections/{connection_id}/request")
    async def proxy(connection_id: str, request: Request) -> Response:
        principal = cast(Principal, request.state.principal)
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
            result = await broker.request(
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
