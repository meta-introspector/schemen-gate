"""Exact-request delegation statements; authority comes only from configured roots."""

from __future__ import annotations

from typing import Any

from ._profile import require
from .crypto import commitment, valid, verify

DELEGATION = "schemen-delegation+jwt"
APPROVAL = "schemen-approval+jwt"


def approver(
    chain: list[str], *, signer: str, root_keys: tuple[str, ...], request_hash: str, audience: str
) -> int | None:
    require(type(chain) is list and len(chain) <= 3)
    if not chain:
        require(signer in root_keys, "untrusted_approver")
        return None
    expected: str | None = None
    expiry: int | None = None
    previous = "root"
    seen: set[str] = set()
    depth = 3
    for token in chain:
        claims, key = verify(token, DELEGATION)
        valid(claims, key, audience)
        require(key in root_keys if expected is None else key == expected, "untrusted_delegation")
        require(key not in seen, "delegation_cycle")
        seen.add(key)
        require(
            set(claims)
            == {
                "iss",
                "aud",
                "iat",
                "exp",
                "jti",
                "request_sha256",
                "may_act",
                "parent_sha256",
                "depth",
                "actions",
            }
        )
        require(claims["request_sha256"] == request_hash and claims["parent_sha256"] == previous)
        require(claims["actions"] == ["approve"])
        require(type(claims["depth"]) is int and 0 <= claims["depth"] < depth)
        require(type(claims["may_act"]) is dict and set(claims["may_act"]) == {"sub"})
        delegate = claims["may_act"]["sub"]
        require(type(delegate) is str and 16 <= len(delegate) <= 128 and delegate not in seen)
        require(expiry is None or claims["exp"] <= expiry)
        depth, expiry, expected = claims["depth"], claims["exp"], delegate
        previous = commitment(token)
    require(expected == signer, "wrong_delegate")
    return expiry


def approval(
    token: str, chain: list[str], row: dict[str, Any], roots: tuple[str, ...], audience: str
) -> dict[str, Any]:
    claims, key = verify(token, APPROVAL)
    valid(claims, key, audience)
    require(
        set(claims)
        == {
            "iss",
            "aud",
            "iat",
            "exp",
            "jti",
            "request_id",
            "request_sha256",
            "chain_sha256",
            "decision",
        }
    )
    require(claims["request_id"] == row["id"] and claims["request_sha256"] == row["hash"])
    require(claims["chain_sha256"] == commitment(chain))
    require(claims["decision"] in {"approve", "deny"})
    expiry = approver(
        chain, signer=key, root_keys=roots, request_hash=row["hash"], audience=audience
    )
    require(expiry is None or claims["exp"] <= expiry)
    return claims
