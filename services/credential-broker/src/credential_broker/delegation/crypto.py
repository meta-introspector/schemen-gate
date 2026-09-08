"""Ed25519-only JOSE, domain-separated statements, and RFC 9449 proof checks."""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any, cast
from urllib.parse import urlsplit

from joserfc import jwt
from joserfc.jwk import OKPKey

from credential_broker.models import canonical

from ._jose_util import digest, header, uri
from ._profile import Denied, require

PREFIX = "schemen-"


def commitment(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def public(value: Any) -> OKPKey:
    require(type(value) is dict and set(value) == {"kty", "crv", "x"})
    require(value["kty"] == "OKP" and value["crv"] == "Ed25519")
    try:
        return OKPKey.import_key(value)
    except Exception:
        raise Denied("invalid_request") from None


def public_dict(key: OKPKey) -> dict[str, Any]:
    data = key.as_dict(private=False)
    return {name: data[name] for name in ("kty", "crv", "x")}


def sign(key: OKPKey, kind: str, claims: dict[str, Any]) -> str:
    return jwt.encode(
        {"alg": "Ed25519", "typ": kind, "jwk": public_dict(key)},
        claims,
        key,
        algorithms=["Ed25519"],
    )


def verify(token: str, kind: str, *, expected: OKPKey | None = None) -> tuple[dict[str, Any], str]:
    try:
        h = header(token)
        require(set(h) == {"alg", "typ", "jwk"})
        require(h["alg"] == "Ed25519" and h["typ"] == kind)
        key = public(h["jwk"])
        require(expected is None or key.thumbprint() == expected.thumbprint())
        decoded = jwt.decode(token, key, algorithms=["Ed25519"])
        return decoded.claims, key.thumbprint()
    except Exception:
        raise Denied("invalid_signature") from None


def envelope(key: OKPKey, audience: str, *, ttl: int = 60) -> dict[str, Any]:
    now = int(time.time())
    return {
        "iss": key.thumbprint(),
        "aud": audience,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_urlsafe(24),
    }


def valid(claims: dict[str, Any], issuer: str, audience: str, *, maximum: int = 300) -> None:
    require(claims.get("iss") == issuer and claims.get("aud") == audience)
    require(type(claims.get("iat")) is int and type(claims.get("exp")) is int)
    now = int(time.time())
    require(claims["iat"] <= now + 5 and now < claims["exp"] <= claims["iat"] + maximum)
    require(claims["exp"] > claims["iat"])
    require(type(claims.get("jti")) is str and 16 <= len(claims["jti"]) <= 128)


def dpop(key: OKPKey, url: str, nonce: str, token: str | None = None) -> str:
    claims: dict[str, Any] = {
        "jti": secrets.token_urlsafe(24),
        "iat": int(time.time()),
        "htm": "POST",
        "htu": url,
        "nonce": nonce,
    }
    if token is not None:
        claims["ath"] = digest(token)
    return sign(key, "dpop+jwt", claims)


def check_dpop(
    proof: str, url: str, nonce: str, key: str, token: str | None = None
) -> tuple[str, int]:
    try:
        claims, thumb = verify(proof, "dpop+jwt")
        require(thumb == key and claims.get("htm") == "POST")
        target = claims.get("htu")
        require(type(target) is str)
        target = cast(str, target)
        require(not urlsplit(target).query and not urlsplit(target).fragment)
        require(uri(target) == uri(url))
        require(claims.get("nonce") == nonce, "use_dpop_nonce")
        now = int(time.time())
        require(type(claims.get("iat")) is int and now - 30 <= claims["iat"] <= now + 5)
        require(type(claims.get("jti")) is str and 16 <= len(claims["jti"]) <= 128)
        if token is not None:
            require(claims.get("ath") == digest(token))
        return claims["jti"], claims["iat"] + 35
    except Denied as exc:
        if exc.code == "use_dpop_nonce":
            raise
        raise Denied("invalid_dpop_proof") from None
