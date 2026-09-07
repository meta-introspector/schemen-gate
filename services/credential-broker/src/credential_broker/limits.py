"""Bounded process-local admission budgets, shared by a principal's tokens."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

from .models import BrokerError, Principal


class Limits:
    def __init__(
        self,
        principals: list[Principal],
        *,
        concurrent: int = 16,
        per_principal: int = 4,
        burst: int = 30,
        per_second: float = 2,
    ):
        self.concurrent, self.per_principal = concurrent, per_principal
        self.burst, self.per_second = burst, per_second
        self._lock = threading.Lock()
        self._active = 0
        self._states = {
            (p.tenant, p.subject): [0, float(burst), time.monotonic()] for p in principals
        }

    @contextmanager
    def admit(self, principal: Principal) -> Iterator[None]:
        with self._lock:
            state = self._states[(principal.tenant, principal.subject)]
            now = time.monotonic()
            state[1] = min(self.burst, state[1] + (now - state[2]) * self.per_second)
            state[2] = now
            if self._active >= self.concurrent or state[0] >= self.per_principal or state[1] < 1:
                raise BrokerError(429, "request_budget_exceeded")
            self._active += 1
            state[0] += 1
            state[1] -= 1
        try:
            yield
        finally:
            with self._lock:
                self._active -= 1
                state[0] -= 1
