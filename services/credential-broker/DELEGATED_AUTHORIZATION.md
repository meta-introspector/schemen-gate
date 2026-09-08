# Authenticated bindings at every hop

Broker 0.3.0 provides an opt-in `credential_broker.delegation` application module.
It implements a signed request, approval pause, delegated decision, authenticated
callback, key-bound redemption, exact-operation execution, and signed result.
The Calendar adapter connects this flow to the existing per-call credential
custody service. Substrate is not required.

This is an explicit application profile, with executable tests and a local demo.
It is not a complete OAuth authorization server, CIBA implementation, external
provider conformance result, or general-purpose federation service. The existing
`schemen-broker serve` command does not mount these endpoints automatically.

## Install and run the demonstration

Prepare the core Gate package from this checkout using the
[Calendar installation instructions](CALENDAR_ONE_OFF.md#install-and-approve).
Then, from this service directory, using the same environment:

```sh
python -m pip install -r requirements.lock -r requirements-gate.lock -r requirements-delegation.lock
python -m pip install --no-deps --no-build-isolation '.[delegation]'
python -m credential_broker.delegation.demo
```

The demo creates temporary synthetic signing keys and encrypted databases. It
uses separate service and callback ASGI applications with a counted executor.
It verifies the callback and result, rejects a changed event, restarts the
service, executes once, restarts again, and rejects a repeat. It makes no Google
call. `--output /path/to/new-report.json` saves a redacted trace in a new 0600 file.

## Protocol

1. The caller signs a complete request: exact RAR Calendar operation, tenant,
   connection generation, service audience, registered callback identifier,
   nonce, expiry, and unique identifier. Identity is the signing key thumbprint;
   self-asserting an identity supplies no approval authority.
2. The service validates the caller's registered return-channel binding and
   persists an encrypted pending record. Its signed acknowledgement binds the
   request commitment and caller nonce. An actor token identifies the key holder
   but does not authorize execution.
3. A configured owner or authorized delegate retrieves a signed review of the
   original signed request. Approvers can inspect the actual proposal before
   deciding, rather than relying on model-generated descriptions.
4. An owner signs directly or delegates approval for this exact request to
   another key. Each delegation binds its parent commitment, delegate, operation
   commitment, expiry, and decreasing remaining depth. The maximum depth is
   three. Cycles and expanding lifetimes are refused.
5. The approver signs approve or deny, including the request ID, request
   commitment, and delegation-chain commitment. The service checks configured
   owner roots and the full chain, then stores the decision and a signed callback.
6. The callback is posted only to the configured HTTPS endpoint. The caller's
   inbox pins the service key and verifies audience, recipient key, request,
   nonce, resource, and expiry. Exact retries are idempotent. Failed delivery
   preserves the same signed outbox message for a trusted dispatcher to retry.
7. The caller presents callback and actor tokens to the token endpoint using
   Token Exchange fields, authenticates with `private_key_jwt`, and supplies a
   fresh DPoP proof. Successful exchange consumes the approval's issuance state
   and returns one audience- and key-bound access token with an exact-call Gate.
8. The executor verifies a fresh DPoP proof and the actual operation against
   Gate, then atomically consumes the execution budget before invoking the
   credential source. The caller verifies the signed result; authenticated result
   retrieval does not reopen execution authority.

The approval path is linear, with configured alternative owner keys. This does
not implement AND/quorum composition across independent approval branches.

## Standards and application-specific semantics

All new JWS signatures use the explicit `Ed25519` algorithm identifier from
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864), with Ed25519 OKP keys. The
deprecated polymorphic `EdDSA` identifier and other algorithms are not silently
accepted. Gate authentication and encrypted storage remain symmetric
cryptographic operations; signatures do not replace encryption.

[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) supplies token-exchange request
and response fields. [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) supplies
`authorization_details`; the module defines the closed application type
`urn:schemen:authorization:calendar-event-v1`, requiring `actions=["create"]`,
the configured resource in `locations`, and the existing narrow Calendar `call`.
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) supplies JWT client assertion
parameters. [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) supplies DPoP
proofs, token-key binding, token hashes, and nonce challenges. Exact body binding
is independently enforced by Gate.

The request/review/approval/callback statement types, callback-token exchange
profile, delegation depth policy, and evidence commitments are application
semantics. They are not advertised as CIBA or automatic interoperability with
arbitrary OAuth clients. `act` history is not used as independent authority.

## Application wiring

Construct `service.Config` with the issuer URL, resource URL ending in
`/calendar/execute`, tenant, connection generation, authorized owner key
thumbprints, and `ReturnChannel` entries binding each callback identifier to a
caller key and HTTPS destination. Construct `Service` with an Ed25519 private
signing key, a separate 32-byte Gate root, and a database path inside a 0700
owner-controlled directory. Persist the keys through the application's secret
management. Startup refuses a changed trust/configuration/key identity against
an existing database.

`api.application(service, executor, callbacks)` returns the FastAPI application.
`api.callback_application(inbox)` returns the caller-side callback application.
`transport.HttpCallbacks` accepts only explicitly configured destinations,
disables environment proxies and redirects, and applies a total timeout.

For Calendar, construct `execution.CalendarExecutor` with a `CalendarCallService`,
its administrator principal, a trusted account-specific `CredentialSource`,
and the configured connection generation. The adapter verifies tenant and
connection before acquiring the credential. The source is invoked only after
the outer authorization budget is committed as consumed. It must independently
establish the Google account provenance; this module does not implement Google
OAuth linking or refresh.

| Endpoint | Cryptographic input |
| --- | --- |
| `POST /requests` | Signed exact proposal |
| `POST /reviews` | Signed request from owner or exact-request delegate |
| `POST /approvals` | Signed approve/deny plus delegation statements |
| `POST /revocations` | Signed deny from an authorized principal |
| `POST /token` | Token Exchange, JWT client assertion, DPoP proof |
| `POST /calendar/execute` | DPoP-bound access token, fresh proof, exact call |
| `POST /results` | Fresh signed request from the original caller |

## State, custody, and operational boundaries

Pending proposals and tokens are encrypted with AES-GCM under a separately
derived storage key; row identity is authenticated as AAD. SQLite transactions
serialize issuance, consumption, and replay checks across service instances.
Restart does not reset those records. Request capacity is 1,000 retained records;
replay capacity is 10,000 live entries. The service refuses new work at capacity
rather than deleting evidence or live grants. Retention and key rotation require
an explicit operator process. Restoring an older database with its original keys
is not protected by an independent anti-rollback authority.

Per-request revocation is checked before issuance and execution. Delegation
expiry bounds the resulting grant. There is no global federation revocation
feed. A committed execution is never retried automatically after failure,
cancellation, or restart; a provider outcome can remain unknown.

The Calendar bridge retains the broker's destruction boundary: its independent
per-call decryption key and owned custody are destroyed, with the broker's signed
receipt. It does not erase issuer-owned token copies, revoke the upstream Google
grant, or prove erasure of all Python/native/OS memory copies.

The module needs operator TLS termination, request admission/rate limits,
protected key custody, callback retry scheduling, and an approval UI or agent
policy integration before external operation. HTTP input is size-limited and
body reading is deadline-limited; that does not substitute for edge admission.
Human and agent approvers use the same cryptographic interface; a human-facing
signing ceremony is not included. No production-readiness or full RFC conformance
claim is made by this version.

## Verification

The [standards and delegation suite](proofs/oauth-delegation/README.md) exercises
all signed hops, independent raw Ed25519 signature verification, trust-root and
delegate substitution, callback tampering/retries, credential isolation, Gate
body binding, encrypted-state tampering, revocation, restart and concurrent use.
The Calendar integration test uses the actual custody service with a simulated
HTTP provider. The installed-wheel demo additionally runs with Python isolated
mode to verify package independence from checkout/proof imports.
