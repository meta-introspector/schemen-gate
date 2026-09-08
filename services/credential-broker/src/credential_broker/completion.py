"""Finish mandatory custody transactions despite repeated caller cancellation."""

from __future__ import annotations

import asyncio
from typing import TypeVar

T = TypeVar("T")


async def settle(task: asyncio.Task[T]) -> tuple[T, bool]:
    cancelled = False
    while True:
        try:
            return await asyncio.shield(task), cancelled
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            cancelled = True
