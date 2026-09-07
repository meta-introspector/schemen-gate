from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from starlette.concurrency import run_in_threadpool

from .models import BrokerError, Principal, ProviderPolicy, safe_path
from .vault import Vault

MAX_RESPONSE = 1_048_576
PROVIDER_TIMEOUT = 20.0


@dataclass(frozen=True)
class BrokerResponse:
    status: int
    body: bytes
    content_type: str


class Broker:
    def __init__(self, vault: Vault, providers: dict[str, ProviderPolicy]):
        self.vault, self.providers = vault, dict(providers)

    async def request(
        self,
        principal: Principal,
        connection_id: str,
        method: str,
        path: str,
        query: dict[str, str],
        body: object | None,
    ) -> BrokerResponse:
        path = safe_path(path)
        connection = await run_in_threadpool(self.vault.get, principal.tenant, connection_id)
        if principal.subject not in connection.subjects:
            raise BrokerError(404, "connection_unavailable")
        if connection.expires_at is not None and time.time() >= connection.expires_at:
            raise BrokerError(403, "credential_expired")
        policy = self.providers.get(connection.provider)
        if policy is not None and connection.provider_fingerprint != policy.fingerprint():
            raise BrokerError(409, "provider_policy_changed_reprovision_required")
        if policy is None or not any(route.allows(method, path) for route in policy.routes):
            raise BrokerError(403, "route_denied")
        # No caller-supplied headers, host, URL, cookies, auth, proxies, or redirect policy.
        headers = {
            policy.auth_header: policy.auth_prefix + connection.secret,
            "Accept-Encoding": "identity",
        }
        await run_in_threadpool(
            self.vault.audit, principal.tenant, principal.subject, connection_id, "dispatch", 0
        )
        try:
            # A fresh client prevents cross-connection cookies or auth persistence.
            async with (
                asyncio.timeout(PROVIDER_TIMEOUT),
                httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=10) as client,
            ):
                async with client.stream(
                    method, policy.origin + path, params=query, json=body, headers=headers
                ) as response:
                    if 300 <= response.status_code < 400:
                        raise BrokerError(502, "provider_redirect_blocked")
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise BrokerError(502, "provider_encoding_blocked")
                    chunks = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(chunks) + len(chunk) > MAX_RESPONSE:
                            raise BrokerError(502, "provider_response_limit")
                        chunks.extend(chunk)
                    raw = bytes(chunks)
                    # Refuse echoed credentials instead of returning or partially redacting them.
                    encodings = {
                        connection.secret.encode(),
                        quote(connection.secret, safe="").encode(),
                        base64.b64encode(connection.secret.encode()),
                        json.dumps(connection.secret)[1:-1].encode(),
                    }
                    if any(value in raw for value in encodings):
                        raise BrokerError(502, "provider_secret_echo_blocked")
                    content_type = response.headers.get("content-type", "").split(";", 1)[0]
                    if content_type not in {"application/json", "text/plain"}:
                        content_type = "application/octet-stream"
                    return BrokerResponse(response.status_code, raw, content_type)
        except TimeoutError:
            raise BrokerError(502, "provider_timeout") from None
        except httpx.HTTPError:
            # Never return/log upstream exceptions; they may contain credential-bearing data.
            raise BrokerError(502, "provider_request_failed") from None
