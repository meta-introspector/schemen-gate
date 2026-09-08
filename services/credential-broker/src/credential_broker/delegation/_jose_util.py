"""Strict JWT JSON inspection and the fixed HTTPS endpoint comparison profile."""

from __future__ import annotations

import base64
import hashlib
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

from ._profile import Denied, loads, require


def digest(value: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(value.encode("ascii")).digest())
        .decode()
        .rstrip("=")
    )


def header(token: str) -> dict[str, Any]:
    try:
        parts = token.split(".")
        require(len(parts) == 3 and len(token) <= 32768)
        parsed = []
        for part in parts[:2]:
            parsed.append(loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))))
        require(all(type(p) is dict for p in parsed))
        return cast(dict[str, Any], parsed[0])
    except (ValueError, UnicodeError, AttributeError):
        raise Denied() from None


def uri(value: str) -> str:
    parts = urlsplit(value)
    require(parts.scheme.lower() == "https" and bool(parts.hostname))
    require(parts.username is None and parts.password is None)
    host = cast(str, parts.hostname).lower()
    if parts.port not in (None, 443):
        host += f":{parts.port}"
    return urlunsplit(("https", host, parts.path or "/", "", ""))
