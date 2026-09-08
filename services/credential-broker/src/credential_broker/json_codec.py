"""Unambiguous finite JSON objects on authorization boundaries."""

from __future__ import annotations

import json
from typing import Any, NoReturn

from .models import canonical


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
