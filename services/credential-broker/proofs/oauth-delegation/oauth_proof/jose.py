"""ES256 proof verification using joserfc; the independent test client uses PyJWT."""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

from joserfc import jwt
from joserfc.jwk import ECKey

from .profile import ISSUER, Denied, loads, require


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
        return parsed[0]  # type: ignore[no-any-return]
    except (ValueError, UnicodeError):
        raise Denied() from None


def decode(token: str, key: ECKey, typ: str) -> dict[str, Any]:
    try:
        h = header(token)
        require(h.get("alg") == "ES256" and h.get("typ") == typ)
        require(not set(h).intersection({"crit", "jku", "x5u"}))
        return jwt.decode(token, key, algorithms=["ES256"]).claims
    except Exception:
        raise Denied() from None


def access(token: str, key: ECKey, audience: str, now: int) -> dict[str, Any]:
    claims = decode(token, key, "JWT")
    require(claims.get("iss") == ISSUER and claims.get("aud") == audience)
    for name in ("exp", "iat"):
        require(type(claims.get(name)) is int)
    require(claims["iat"] <= now < claims["exp"])
    require(type(claims.get("sub")) is str and bool(claims["sub"]))
    return claims


def uri(value: str) -> str:
    parts = urlsplit(value)
    require(parts.scheme.lower() == "https" and bool(parts.hostname))
    require(parts.username is None and parts.password is None)
    host = cast(str, parts.hostname).lower()
    if parts.port not in (None, 443):
        host += f":{parts.port}"
    return urlunsplit(("https", host, parts.path or "/", "", ""))


class Proofs:
    """Single-process replay state for this experiment only; caller holds its lock."""

    def __init__(self) -> None:
        self.seen: dict[tuple[str, str], int] = {}

    def verify(
        self,
        token: str,
        method: str,
        url: str,
        *,
        nonce: str,
        expected_key: str | None = None,
        access_token: str | None = None,
    ) -> str:
        try:
            h = header(token)
            public = h.get("jwk")
            require(type(public) is dict and "d" not in public)
            public = cast(dict[str, Any], public)
            require(public.get("kty") == "EC" and public.get("crv") == "P-256")
            key = ECKey.import_key(public)
            claims = decode(token, key, "dpop+jwt")
            thumb = key.thumbprint()
            require(expected_key is None or thumb == expected_key)
            require(claims.get("htm") == method)
            require(type(claims.get("htu")) is str and uri(claims["htu"]) == uri(url))
            require(not urlsplit(claims["htu"]).query and not urlsplit(claims["htu"]).fragment)
            require(claims.get("nonce") == nonce, "use_dpop_nonce")
            now = int(time.time())
            require(type(claims.get("iat")) is int and now - 30 <= claims["iat"] <= now + 5)
            jti = claims.get("jti")
            require(type(jti) is str and 16 <= len(jti) <= 128)
            jti = cast(str, jti)
            if access_token is not None:
                require(claims.get("ath") == digest(access_token))
            self.seen = {k: expiry for k, expiry in self.seen.items() if expiry >= now}
            require((thumb, jti) not in self.seen)
            self.seen[(thumb, jti)] = claims["iat"] + 35
            return thumb
        except Denied as exc:
            if exc.code == "use_dpop_nonce":
                raise
            raise Denied("invalid_dpop_proof") from None
        except Exception:
            raise Denied("invalid_dpop_proof") from None
