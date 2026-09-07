# Credential broker security contract

This contract applies to the separately installed `schemen-credential-broker`
package, not to the core library's cryptographic or model-boundary claims.
Use the root [private reporting policy](../../SECURITY.md) for vulnerabilities;
include the broker version and repository commit, never real credentials.

## Trust model

A caller may control every request byte, possess an agent token, attempt to
select another connection or tenant, send concurrent requests, and influence
provider response content. Tenant administrators may provision connections
only in their own tenant. They cannot configure arbitrary provider origins
through the API.

The operator configuration, credential broker process, key provider, and OS
service identity are trusted. An approved provider is trusted to receive its
own credential. An agent must not have access to the broker process's memory,
filesystem credentials, administrator token, or master key. Localhost binding
does not establish that isolation.

## Enforced properties and tests

| Property | Implementation and evidence |
| --- | --- |
| Encrypted credential and policy custody | AES-256-GCM with tenant/connection associated data; restart, ciphertext tampering, and tenant-swap tests in `tests/test_broker.py` |
| Key consistency | Authenticated key-check; wrong-key startup, file replacement, stale process, transactional rekey/rollback tests in `tests/test_security.py` |
| Principal and tenant binding | Server-owned token-hash identity map and connection subject ACL; cross-tenant, cross-subject, admin-separation and duplicate-header tests |
| Provider scope | Fixed origin, canonical path, explicit method/route, encrypted configuration fingerprint; injection and origin/route/authentication-drift tests |
| Denial before provider use | Denied requests assert zero calls at an independent HTTP provider; dispatch audit failure also prevents the call |
| TLS peer verification | Untrusted TLS fixture is rejected before receiving an HTTP request or credential |
| Response handling | Redirect, compression and size restrictions; upstream headers suppressed; direct/common encoded secret echoes refused; CLI terminal controls escaped |
| Administrative audit consistency | Store, rotate and delete changes commit atomically with audit; injected failure tests verify rollback |
| Bounded use | Admission budgets, tenant connection quota, ACL cap and audit retention; quota, concurrency, HTTP rejection and retention tests |
| Recovery | Consistent SQLite backup/restore, master-key rotation, and corruption rollback tests |

The implementation uses authenticated encryption from `cryptography`, not a
custom cipher. The minimum dependency version is 50.0.0. The reproducible
dependency snapshot is `requirements.lock`; rescan it as advisories change.
An absence of advisory matches is not a proof of absence of vulnerabilities.

## Capacity and failure semantics

- One broker process: at most 16 active authenticated requests globally and four
  per tenant/subject. A principal's tokens share a burst of 30 and refill at two
  requests per second. Exceeding admission returns 429.
- At most 1,000 connections per tenant and 128 ACL entries per connection.
  Credential replacement remains possible at capacity.
- Local audit retains the latest 100,000 rows. Export before rollover when
  longer retention is required. It is neither signed nor independently
  append-only; authentication and budget rejections need separate telemetry.
- Revocation stops subsequent credential lookups; it cannot recall a request
  that has already obtained its credential and is in flight.
- No automatic retries or exactly-once guarantee. A provider can complete a
  write before a response or post-dispatch audit fails. Reconcile provider
  state before retrying a write; do not interpret every broker error as proof
  that no effect occurred.
- Master-key rotation is offline and transactional. Old-key processes fail
  closed on subsequent database access. Keep old keys for retained old backups.

## Boundaries that are not provided

The permission model is connection/route access. It does not infer human intent,
authenticate individual argument approval, evaluate an exact-operation Gate
grant, or govern a multi-step operation. Allowed calls can be repeated.

Fixed origins and disabled redirects prevent caller-selected forwarding but
are not DNS pinning or a network egress sandbox. Only configure routes whose
provider semantics are understood; an upstream API may itself proxy URLs or
perform broad actions based on arguments.

Secret-echo filtering covers common direct encodings. An approved provider
could transform a credential in other ways; filtering cannot make an arbitrary
malicious recipient safe. Provider results are not semantically verified.

File-based key custody protects a copied database when its key was not copied.
It does not protect a compromised broker host, service identity, or process.
AES-GCM detects record substitution but does not detect rollback of an entire
older database. Availability, backup freshness, and key recovery require
operator controls.

The service does not implement OAuth consent/refresh, distributed quotas,
OIDC/mTLS caller identities, or managed hardware-backed key storage. Deployment
requires appropriate process isolation, ingress TLS, egress policy, monitoring,
backup/key retention and acceptance tests against the actual provider. Running
the local regression suite is necessary evidence, not deployment certification.
