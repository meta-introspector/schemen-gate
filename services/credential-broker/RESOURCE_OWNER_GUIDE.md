# Delegated authorization that resource owners can enforce

An agent should be able to propose an operation, pause while an authorized human
or software principal decides, and resume with cryptographic evidence binding
that decision to the original caller and exact operation. Schemen's optional
broker implements this composition without requiring Substrate.

The useful distinction is between account access and permission for this action.
OAuth supplies account access and can express detailed authorization. Our profile
uses those established mechanisms and adds application-specific commitments,
authenticated callbacks and durable one-use enforcement.

## What is implemented

1. The caller signs its proposal: tenant, account connection, resource, full call,
   return channel, caller key, nonce and expiry. Registration alone grants nothing.
2. The service validates that binding and persists a pending request. It returns
   a signed acknowledgement. No provider credential is acquired at this stage.
3. An authorized approver reviews the signed original request. A resource-owner
   key may approve directly or delegate approval through a bounded chain. Each
   child commits to its parent and cannot expand the operation or lifetime.
4. Approval produces a service-signed callback addressed to the original caller.
   The caller verifies its pinned service key and original nonce and commitment.
5. The caller exchanges the callback and actor token using signed client
   authentication and DPoP. The issued grant binds the exact operation and key.
6. The execution boundary checks the actual call against the Gate, atomically
   consumes the authorization, then acquires a per-call credential and dispatches.
7. The caller receives a signed result. A failed or uncertain dispatch does not
   reopen authorization. Result retrieval is separate from execution.

New application signatures use Ed25519. Human and software approvers use the same
cryptographic interface; the implementation does not yet supply a human signing
UI. Linear delegation is implemented, not arbitrary quorum or approval graphs.
See the [integration contract](DELEGATED_AUTHORIZATION.md) for exact interfaces
and operational requirements.

## Recommendation to resource owners

Offer an operation authorization endpoint alongside ordinary account linking.
Accept a typed proposal, authenticate the requesting key, resolve the actual
resource owner from your own account records, and return a pending transaction.
Let that owner approve directly or authorize an explicitly bounded delegate.
Return a signed decision to the registered caller, and make the resource API
verify the resulting grant against the actual operation before any effect.

The account holder who may authorize access, the API operator that enforces it,
and the authorization service issuing a grant are distinct roles. A service
signature must represent an authority relationship you established; a valid
signature or a claimed account name does not establish ownership by itself.

A practical first profile should specify:

- **A closed action schema.** Bind account, resource ID, operation, normalized
  arguments, output projection, expiry and use limit. Reject extra fields. For a
  Calendar insert, include attendees and notification behavior if you support
  them; do not let an omitted policy field become an implicit permission.
- **Scoped trust.** Register issuer and owner keys against the tenant, resource
  and allowed authorization role. Validate issuer, audience, key and algorithm.
  TLS certificate authorities authenticate transport endpoints; a certificate
  chain alone does not authorize an issuer to approve somebody's calendar.
- **Authenticated delegation.** Require every link to identify its delegator,
  delegate, parent commitment, scope, expiry and remaining delegation depth.
  Evaluate the chain at the resource boundary. Never infer transitive trust.
- **A verifiable pause and return.** Persist request identity and state before
  returning pending. Bind approval and callback to the caller's key, original
  nonce, request commitment and registered destination. Make delivery retries
  idempotent, and keep denial distinct from timeout.
- **Possession and exact-call checks.** Use sender-constrained tokens and verify
  their audience. DPoP binds token possession and HTTP method/URI; separately bind
  the request body and relevant query arguments to the approved operation.
- **Complete enforcement.** All routes exercising this delegated authority must
  encounter the check, including raw API endpoints, SDK shortcuts and jobs. A
  broker protects the credentials it controls; independently held credentials
  remain independently usable under their own authorization policy.
- **Atomic use and honest outcomes.** Consume before dispatch, use provider
  idempotency where available, and record uncertain outcomes for reconciliation.
  At-most-one dispatch attempt is not an exactly-once distributed effect claim.
- **Revocation and custody.** Define grant cancellation, issuer/key rotation,
  restart and database-restore behavior. Define which credential copies you own
  and destroy. A signed deletion receipt is evidence of the signer's recorded
  lifecycle, not proof that another system erased its copies.

Start with RFC 9396 authorization details, RFC 8693 subject/actor token exchange,
RFC 7523 client assertions and RFC 9449 DPoP. Document your application profile and
conformance tests; do not advertise custom callbacks as a standardized OAuth
flow. Schemen uses the fully specified Ed25519 JOSE algorithm from RFC 9864.

## Google Calendar: broker adoption today, native adoption proposal

Today our broker calls Google's Calendar API using an ordinary Google access
token. Google authorizes that token using its account permissions and scopes.
Our broker validates the delegated operation before using it. This does not
establish that Google validates our Gate, callback, owner keys or chain.

A native resource-owner integration would move the operation check into the API
operator's trusted enforcement path. It could avoid exporting a broad provider
credential to a broker: issue a short-lived, audience- and key-bound operation
grant and validate it directly at dispatch. This is a proposal, not a claim of
current Google support.

For Google testing, use the [live acceptance procedure](GOOGLE_CALENDAR_ACCEPTANCE.md).
The current writable profile only inserts one event into the authenticated
account's primary calendar, with an explicit event ID and `sendUpdates=none`.
It rejects attendees and recurrence. A separate read-only access preflight is
provided; it does not establish that the delegated write flow worked.

## Falsifiable acceptance conditions

Before any approval, provider dispatch count must remain zero. Mutating the
caller, connection, callback, parent link, expiry, target or approved arguments
must fail without dispatch. A valid approved call may dispatch once; concurrent
attempts and restarts must not permit a second dispatch. A callback signed by an
untrusted key must not unblock the caller. Cancellation must leave the grant
consumed if dispatch may have begun. Credential acquisition must occur after
consumption. Verify receipts with independently pinned keys and report custody
limits separately from provider access revocation.

## Standards and provider references

- [OAuth Token Exchange, RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
- [Rich Authorization Requests, RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)
- [JWT client authentication, RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)
- [DPoP, RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)
- [Fully specified JOSE algorithms, RFC 9864](https://www.rfc-editor.org/rfc/rfc9864)
- [Google Calendar scopes](https://developers.google.com/workspace/calendar/api/auth)
- [Google installed-application OAuth and PKCE](https://developers.google.com/identity/protocols/oauth2/native-app)
