# One approved Google Calendar call

Broker 0.2.0 adds an optional exact-operation Gate path for one event on the
Google account's primary calendar. The trusted issuer supplies an access token
for that call. The agent receives an AAD-bound grant and never receives the
provider credential. Substrate is not required.

The existing reusable connection API remains a separate permission model.
One-off credentials are never inserted into its vault and cannot be used
through its raw request route.

## Install and approve

Install the core Gate package and this service's `gate` extra in the same
isolated environment. From the service directory in this checkout:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock -r requirements-gate.lock
.venv/bin/python -m pip install 'setuptools==84.0.0' 'wheel==0.47.0'
.venv/bin/python ../../scripts/stamp_release.py \
  --version 1.0.2 --repository https://github.com/sekosai/schemen-gate \
  --commit "$(git rev-parse HEAD)"
.venv/bin/python -m pip install --no-deps --no-build-isolation ../..
.venv/bin/python -m pip install --no-deps --no-build-isolation '.[gate]'
```

These commands install Gate from the committed checkout; they do not assume a
matching package-index release exists. CI follows the same source installation
and verifies that core distributions still exclude the broker.
The optional integration fails closed when Gate is unavailable.

Initialize and start the service using the [broker setup](README.md).
The existing server-configured identities accept an optional `channel` field,
defaulting to `default`. It is bound to the authenticated token's identity;
it cannot be asserted in an execution request. Different sessions/channels
require separately configured tokens. This is application-channel binding,
not a TLS exporter or proof of possession for a stolen bearer token.

Prepare `call.json` with this exact narrow shape, adjusting the event ID and
time before approval:

```json
{
  "calendar_id": "primary",
  "send_updates": "none",
  "event": {
    "id": "ec8a63348cd24a2ba3eb25a7484179f1",
    "summary": "One approved meeting",
    "start": {"dateTime": "2026-09-09T17:00:00Z"},
    "end": {"dateTime": "2026-09-09T17:30:00Z"}
  }
}
```

The trusted issuer obtains an access token through its own Google OAuth flow
and writes it to an owner-only file. For a user-owned primary calendar,
`calendar.events.owned` is a relevant accepted scope. The issuer is responsible
for the credential's account provenance. This service does not implement the
OAuth consent/refresh flow or independently attest the token's account owner.
See [Google's scope definitions](https://developers.google.com/workspace/calendar/api/auth).

Protect the call document (`chmod 600 call.json`), then approve once using the
administrator's protected token:

```sh
.venv/bin/schemen-broker calendar-approve \
  --token-file local-secrets/admin.token \
  --credential-file /path/to/protected-google-access-token \
  --subject agent --channel default --expires-in 60 \
  --call-file call.json --grant-file approved-call.json
```

The grant file is created exclusively with mode 0600. It contains the approved
call, encrypted Gate token and receipt-verification key, but no Google access
token. It must reach the agent through a trusted channel. Protect the original
credential file separately: the broker does not erase issuer-owned files.

Execute from the authorized agent channel:

```sh
.venv/bin/schemen-broker calendar-execute \
  --token-file local-secrets/agent.token --grant-file approved-call.json
```

The CLI verifies the signed receipt against the issuer key pinned in the
trusted grant file. Repeating this command cannot dispatch again. A response
key presented by an untrusted party cannot establish its own authenticity.

## Closed profile and HTTP contract

The target is exactly
`POST https://www.googleapis.com/calendar/v3/calendars/primary/events`, with
`sendUpdates=none`. Required event fields are explicit `id`, `summary`, `start`
and `end`; `description` is optional. Unknown fields, other calendars,
attendees, recurrence, attachments, conferencing and notification changes are
rejected. An explicit event ID supports reconciliation after an ambiguous
outcome; it is not an exactly-once guarantee from Google.
See [events.insert](https://developers.google.com/workspace/calendar/api/v3/reference/events/insert)
and [custom event IDs](https://developers.google.com/workspace/calendar/api/guides/create-events).

| Endpoint | Authority |
| --- | --- |
| `POST /v1/calendar-calls` | Administrator approves exact call, target subject/channel, per-call credential, and TTL of 1–300 seconds |
| `POST /v1/calendar-calls/{id}/execute` | Authenticated target subject/channel submits exactly `gate` and `call` |
| `GET /v1/calendar-calls/{id}/receipt` | Same target identity/channel retrieves a completed receipt |
| `DELETE /v1/calendar-calls/{id}` | Tenant administrator revokes a pending call |
| `GET /v1/calendar-calls/issuer` | Authenticated caller discovers issuer key and audience through the trusted service connection |

The approval body has exactly `subject`, `channel`, `credential`, `expires_in`
and `call`. Execution has exactly `gate` and `call`. Caller-selected URLs,
providers, raw methods, headers and channel assertions are not accepted here.

## AAD and single-use reasoning

The canonical contract binds the tenant, subject, authenticated request/result
channel, issuer subject, broker audience, custody-instance owner, random grant/credential generation,
expiry, one-use limit, provider policy fingerprint, response policy and entire
method/path/query/body. Public Gate exact-operation APIs authenticate its
commitment as AAD. Verification independently rebuilds the expected contract;
the submitted token cannot select its own expected authority.

The same complete contract bytes are AAD for the per-call credential's separate
AES-GCM envelope. Its random 256-bit key exists only in process-local custody;
it is not derived from the long-lived vault key and is never persisted.

```mermaid
sequenceDiagram
    participant I as Trusted issuer
    participant B as Broker
    participant A as Agent channel
    participant G as Google Calendar
    I->>B: Exact call + per-call credential
    B-->>I: Gate grant + pinned receipt key
    I->>A: Approved grant through trusted channel
    A->>B: Authenticated exact execution
    B->>B: Verify AAD; commit consumed + audit
    B->>B: Pop custody; decrypt; zero owned key
    B->>G: Exact request + Authorization header
    G-->>B: Provider response
    B->>B: Persist signed local disposition
    B-->>A: Approved event ID, status, receipt
```

Every dispatch follows a successful `pending → consumed` SQLite transaction
that also records dispatch intent. Concurrent attempts cannot both perform
that transition. Consumption precedes credential release and is never undone
on timeout, cancellation or provider failure. A restored old ledger row cannot
restore a removed RAM key. Execution and revocation must reach the owning custody instance; another
instance is rejected before consumption and cannot claim destruction of a key
it does not own. A restarted process loses even pending keys and rejects those
grants without issuing a destruction receipt; issue fresh approvals after
restart. Old pending rows count toward limits until their short expiry.

## What the destruction evidence establishes

Tests establish that the owned mutable key buffer is zero, its ciphertext and
custody references are removed, and neither a replay nor a restored pending row
can cause another release. On successful take, the key is destroyed before
provider I/O. Revocation, expiry cleanup and shutdown also destroy pending keys.
The service sweeps expired custody once per second. Limits are 64 pending
credentials process-wide, 16 pending calls per tenant, and 1,000 live ledger
rows; ledger rows are eligible for removal after expiry, so retain receipts
outside the service when longer evidence retention is needed.

Receipts are Ed25519-signed accounts of local consumption, credential-custody
destruction and observed provider outcome, bound to the grant, AAD digest,
channel and returned event ID. They are not independent evidence of host
memory erasure. Python/native/TLS copies, swap, snapshots, issuer-owned token
files and Google's copies are outside the zeroization observation. The service
does not revoke Google's project-wide OAuth grant after each call; Google
[revocation semantics](https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke)
can affect related access/refresh tokens and take time to propagate.

## Output and failure evidence

The result channel releases only the approved event ID, provider status, and
signed disposition. It never forwards arbitrary provider bodies or headers.
`confirmed` requires HTTP 200 and an unambiguous JSON object whose `id` matches
the approved ID and whose `status` is `confirmed`. Wrong/malformed success responses are `invalid_provider_response`; a
transport error or timeout is `unknown`. These are observations of the trusted
provider's response, not independent verification of event semantics.

Fault tests cover failures before consumption, after consumption, during
provider I/O, and during receipt persistence. A write can occur before a lost
response. An absent receipt or broker error must not be interpreted as proof
that no event exists. The grant remains consumed, and retries need reconciliation
and fresh approval.

The retained tests include exact HTTP dispatch, field-by-field AAD tampering,
channel substitution, concurrent replay, restart/ledger rollback, SQLite
transaction/audit failures, cancellation, expiry, revocation, key zeroization,
receipt signature checks, and the actual CLI path. Paired synthetic secrets
are compared across the declared agent output projection, logs and persistence;
provider authorization is the intended exception. Timing and all possible
covert channels are not claimed to be noninterfering.

Tests use an independent local Calendar-shaped HTTP provider plus Gate's actual
cryptography. No live Google account was modified by this test suite. A
production-provider acceptance call remains a separate operation with a real
credential and explicitly chosen event.
