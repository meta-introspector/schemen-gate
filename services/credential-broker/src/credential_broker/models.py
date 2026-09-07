from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit


class BrokerError(Exception):
    def __init__(self, status: int, code: str):
        self.status, self.code = status, code
        super().__init__(code)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value):
        raise BrokerError(400, "invalid_identifier")
    return value


def safe_path(path: str) -> str:
    if (
        not isinstance(path, str)
        or len(path) > 2048
        or not re.fullmatch(r"/[A-Za-z0-9/_~.\-]*", path)
        or "//" in path
        or any(p in {".", ".."} for p in path.split("/"))
    ):
        raise BrokerError(400, "invalid_path")
    return path


@dataclass(frozen=True)
class Principal:
    tenant: str
    subject: str
    admin: bool = False

    def __post_init__(self) -> None:
        identifier(self.tenant)
        identifier(self.subject)
        if type(self.admin) is not bool:
            raise ValueError("admin must be boolean")


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    prefix: bool = False

    def __post_init__(self) -> None:
        safe_path(self.path)
        if self.method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("unsupported method")
        if type(self.prefix) is not bool or (self.prefix and not self.path.endswith("/")):
            raise ValueError("prefix routes must end with slash")

    def allows(self, method: str, path: str) -> bool:
        return method == self.method and (
            path.startswith(self.path) if self.prefix else path == self.path
        )


@dataclass(frozen=True)
class ProviderPolicy:
    origin: str
    routes: tuple[Route, ...]
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    allow_loopback_http: bool = False

    def __post_init__(self) -> None:
        parsed = urlsplit(self.origin)
        secure = parsed.scheme == "https"
        local = (
            self.allow_loopback_http and parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
        )
        if (
            not (secure or local)
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or not self.routes
        ):
            raise ValueError("provider must be a fixed HTTPS origin with explicit routes")
        if (self.auth_header, self.auth_prefix) not in {
            ("Authorization", "Bearer "),
            ("X-API-Key", ""),
        }:
            raise ValueError("only bearer and X-API-Key credentials are supported")

    def fingerprint(self) -> str:
        return hashlib.sha256(canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class Connection:
    provider: str
    subjects: tuple[str, ...]
    secret: str = field(repr=False)
    expires_at: float | None = None
    provider_fingerprint: str | None = None

    def __post_init__(self) -> None:
        identifier(self.provider)
        if not self.subjects or len(self.subjects) > 128:
            raise BrokerError(400, "subjects_required")
        for subject in self.subjects:
            identifier(subject)
        if not isinstance(self.secret, str) or not re.fullmatch(
            r"[\x21-\x7e]{16,8192}", self.secret
        ):
            raise BrokerError(400, "invalid_credential")
        if self.expires_at is not None:
            import math

            if (
                type(self.expires_at) not in {int, float}
                or not math.isfinite(self.expires_at)
                or self.expires_at <= 0
            ):
                raise BrokerError(400, "invalid_expiry")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
