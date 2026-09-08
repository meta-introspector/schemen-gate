"""Callbacks only to configured destinations. Notifications carry signed opaque handles."""

from __future__ import annotations

import asyncio
from typing import Protocol

import httpx

from ._profile import require


class Callbacks(Protocol):
    async def send(self, destination: str, statement: str) -> None: ...


class HttpCallbacks:
    def __init__(
        self, allowed: tuple[str, ...], *, transport: httpx.AsyncBaseTransport | None = None
    ):
        self.allowed, self.transport = allowed, transport

    async def send(self, destination: str, statement: str) -> None:
        require(destination in self.allowed and destination.startswith("https://"))
        async with asyncio.timeout(5):
            async with httpx.AsyncClient(
                transport=self.transport, trust_env=False, follow_redirects=False, timeout=5
            ) as client:
                async with client.stream(
                    "POST", destination, json={"statement": statement}
                ) as response:
                    require(response.status_code in {200, 204}, "callback_delivery_failed")
