# OAuth and authenticated-hop verification

This directory contains the original ES256 standards-composition experiment and
verification for the installable Ed25519 delegated-authorization module.

The current suite has **133 tests**: 69 baseline standards-composition tests and
64 tests added for signed requests, delegated approvals, callbacks, durable
redemption, and Calendar custody integration. The baseline experimental server
is not used by the installed module.

See [Delegated authorization](../../DELEGATED_AUTHORIZATION.md) for the supported
profile, application wiring, installation, runnable demo, and operational limits.

## Run

Use the Gate-enabled environment from the service installation instructions.
From this directory:

```sh
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pytest -q --junitxml=delegation-tests.xml
```

The configuration imports the broker source from `../../src`. CI runs these tests
on Python 3.11, 3.12, and 3.14 and uploads JUnit results alongside the broker suite.
A configured CI matrix is not evidence that a particular unpushed change has
passed hosted CI; inspect the run for the commit being reviewed.

## Evidence boundaries

- The baseline uses PyJWT client proofs and joserfc verification, plus independent
  PyJWT verification of server-issued JWTs. It exercises Token Exchange, RAR, and
  DPoP over in-process HTTP boundaries.
- The installed module uses the fully specified Ed25519 JOSE algorithm. Tests
  independently verify the raw signatures using cryptography. PyJWT 2.13.0 does
  not advertise the new Ed25519 algorithm identifier, so no cross-library OAuth
  client compatibility is claimed for that identifier.
- The signed flow tests authenticated owner/delegate review and approval,
  cryptographically bound callbacks, client JWT assertions, DPoP nonce challenges,
  exact-operation Gate enforcement, encrypted SQLite state, restart persistence,
  revocation, concurrent service instances, and signed result retrieval.
- The Calendar bridge test uses the actual broker custody service and a simulated
  HTTP provider. It verifies credential acquisition after consumption, destruction
  of the owned per-call key, the signed custody receipt, and secret-canary absence
  from outward results and persisted databases.
- The demo uses synthetic keys and a counted executor. Neither this suite nor the
  demo makes a live Google Calendar write. Full RFC conformance, independent
  authorization-server interoperability, and production readiness are not inferred.

The original experimental `oauth_proof` code intentionally has in-memory state
and fixed example identities. It is retained as a falsifiable baseline, not as a
production server. Its private-key and trust assumptions must not be substituted
for those of the installed module.

Primary specifications: [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693),
[RFC 9396](https://www.rfc-editor.org/rfc/rfc9396),
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), and
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864).
