"""One-off calendar HTTP endpoints; the provider credential has no retrieval lane."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from .calendar_calls import CalendarCallService
from .call_receipt import public_key
from .models import BrokerError, Principal, identifier


def register_calendar_routes(
    app: FastAPI,
    payload: Callable[[Request], Awaitable[dict[str, Any]]],
    identities: dict[str, Principal],
) -> None:
    def service() -> CalendarCallService:
        return cast(CalendarCallService, app.state.calendar_calls)

    @app.get("/v1/calendar-calls/issuer")
    def issuer() -> dict[str, str]:
        return {
            "receipt_key": public_key(service().receipt_key),
            "audience": service().ledger.audience,
        }

    @app.post("/v1/calendar-calls", status_code=201)
    async def approve(request: Request) -> dict[str, Any]:
        principal = cast(Principal, request.state.principal)
        if not principal.admin:
            raise BrokerError(403, "admin_required")
        data = await payload(request)
        if not any(
            p.tenant == principal.tenant
            and p.subject == data.get("subject")
            and p.channel == data.get("channel")
            for p in identities.values()
        ):
            raise BrokerError(400, "unknown_call_principal")
        return await run_in_threadpool(service().approve, principal, data)

    @app.post("/v1/calendar-calls/{grant_id}/execute")
    async def execute(grant_id: str, request: Request) -> dict[str, Any]:
        return await service().execute(
            cast(Principal, request.state.principal), identifier(grant_id), await payload(request)
        )

    @app.get("/v1/calendar-calls/{grant_id}/receipt")
    async def receipt(grant_id: str, request: Request) -> dict[str, Any]:
        return await run_in_threadpool(
            service().ledger.receipt, identifier(grant_id), cast(Principal, request.state.principal)
        )

    @app.delete("/v1/calendar-calls/{grant_id}")
    async def revoke(grant_id: str, request: Request) -> Response:
        await run_in_threadpool(
            service().revoke, cast(Principal, request.state.principal), identifier(grant_id)
        )
        return Response(status_code=204)
