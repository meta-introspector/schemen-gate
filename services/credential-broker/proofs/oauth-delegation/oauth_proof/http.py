"""In-process HTTP boundary used to test actual headers, form encoding, and responses."""

from __future__ import annotations

import base64
import secrets
from urllib.parse import parse_qsl, unquote_plus

from credential_broker.models import BrokerError
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .authority import Authority
from .exchange import exchange, execute
from .profile import Denied, loads, require


def app(authority: Authority) -> FastAPI:
    service = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    async def run(request: Request, resource: bool) -> JSONResponse:
        status = 400
        nonce = authority.nonces["resource" if resource else "token"]
        headers = {"Cache-Control": "no-store", "Pragma": "no-cache", "DPoP-Nonce": nonce}
        try:
            require(len(request.headers.getlist("authorization")) == 1, "invalid_client")
            authorization = request.headers["authorization"]
            if resource:
                status = 401
                require(authorization.startswith("DPoP "), "invalid_token")
                credential = authorization[5:]
            else:
                require(authorization.startswith("Basic "), "invalid_client")
                try:
                    raw = base64.b64decode(authorization[6:], validate=True).decode()
                    client, secret = (unquote_plus(v) for v in raw.split(":", 1))
                except (ValueError, UnicodeError):
                    raise Denied("invalid_client") from None
                require(client in authority.principals, "invalid_client")
                require(
                    secrets.compare_digest(secret, authority.principals[client].client_secret),
                    "invalid_client",
                )
                credential = client
            proofs = request.headers.getlist("dpop")
            require(len(proofs) == 1, "invalid_dpop_proof")
            raw_body = await request.body()
            require(len(raw_body) <= 65536, "invalid_request")
            if resource:
                require(
                    request.headers.get("content-type") == "application/json", "invalid_request"
                )
                output = execute(
                    authority, credential, proofs[0], loads(raw_body), actual_url=str(request.url)
                )
            else:
                require(
                    request.headers.get("content-type") == "application/x-www-form-urlencoded",
                    "invalid_request",
                )
                pairs = parse_qsl(raw_body.decode(), keep_blank_values=True, strict_parsing=True)
                form = dict(pairs)
                require(len(form) == len(pairs), "invalid_request")
                output = exchange(
                    authority, credential, form, proofs[0], actual_url=str(request.url)
                )
            return JSONResponse(output, headers=headers)
        except Denied as exc:
            error = "invalid_token" if resource and exc.code == "invalid_grant" else exc.code
            if exc.code == "invalid_client":
                status = 401
                headers["WWW-Authenticate"] = "Basic"
            elif resource:
                headers["WWW-Authenticate"] = f'DPoP error="{error}"'
            return JSONResponse({"error": error}, status_code=status, headers=headers)
        except (BrokerError, ValueError, TypeError, KeyError):
            error = "invalid_token" if resource else "invalid_request"
            if resource:
                headers["WWW-Authenticate"] = f'DPoP error="{error}"'
            return JSONResponse({"error": error}, status_code=status, headers=headers)

    @service.post("/token")
    async def token(request: Request) -> JSONResponse:
        return await run(request, False)

    @service.post("/calendar/execute")
    async def resource(request: Request) -> JSONResponse:
        return await run(request, True)

    return service
