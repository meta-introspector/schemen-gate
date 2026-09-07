# Broker 0.1.2 hardening review

This review covers the optional credential broker's application boundary.
It does not certify a deployment or extend connection/route permissions into
exact-operation authorization. See [SECURITY.md](SECURITY.md) for the complete
trust model and residual limits.

## Reproduced weaknesses and fixes

The four initial regression cases failed against the first repository
integration and passed after the following changes:

| Finding | Reproduction | Fix |
| --- | --- | --- |
| Provider timing was not an absolute deadline | A delayed header response and a continuously dripping body both exceeded the injected short deadline and still succeeded | Cancellable asynchronous HTTP transport with a deadline encompassing connection, headers and body; recovery tested through a subsequent successful request |
| CLI errors could disclose a malformed broker token | A protected token file with a carriage return caused a transport traceback containing the synthetic token | Validate token syntax before constructing headers; top-level CLI failures emit a fixed message without exception text or traceback |
| Admission ended before response delivery | A blocked ASGI body send observed zero active admission slots | ASGI middleware holds admission through the complete response; delivery deadline, cancellation and normal completion all release the slot |

The deadline tests use a short injected limit and real loopback sockets so they
can falsify the boundary without taking 20 seconds per test. The slow-consumer
tests block the ASGI send operation directly, including timeout and cancellation;
they do not claim a load test of a production reverse proxy.

HTTPX's [timeout documentation](https://www.python-httpx.org/advanced/timeouts/)
describes read timeouts as waiting for the next chunk. That inactivity control
remains useful but is now wrapped in an absolute exchange deadline. The
[ASGI middleware boundary](https://www.starlette.io/middleware/#pure-asgi-middleware)
allows admission to cover body delivery as well as endpoint execution.

## Additional controls

- Every HTTP operation except exactly `GET /healthz` requires authentication,
  using the path seen by routing. Trailing-slash redirects and WebSocket
  upgrades are disabled.
- Duplicate content types and encoded request bodies fail before provider
  dispatch. Body length is checked before extending the accumulation buffer.
- Application and test dependencies are pinned by version and published wheel
  SHA-256. The lock excludes source distributions so their transitive build
  requirements cannot silently enter the application install.
- Dedicated CI checks clean installation, dependency consistency, adversarial
  tests, lint/format, strict typing, package contents and the installed CLI on
  Python 3.11, 3.12 and 3.14. The core Gate distribution remains separate.

## Verification and limits

Regression evidence is in `tests/test_hardening.py`; existing HTTP/TLS,
tenant, key-custody, audit and recovery cases remain in the same suite.
Per-commit CI results are authoritative for each interpreter. On 2026-09-07,
a fresh OSV query for the 24 exact dependency versions found no listed
advisories; advisory databases change and do not establish source correctness.

The approved provider still receives its credential and may perform a write
before timeout or cancellation. The broker performs no automatic retries and
cannot recall that effect. Reconcile provider state before retrying.

Host/process isolation, trusted provider semantics, ingress/egress controls,
backup/key retention, and acceptance against a real provider remain necessary.
The code review and regression suite do not constitute an independent
penetration test or formal verification.
