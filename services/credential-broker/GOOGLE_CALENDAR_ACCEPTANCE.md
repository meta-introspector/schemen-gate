# Google Calendar live acceptance

Status: **live authenticated access not yet verified**. An operator-selected
Google OAuth client or approved credential source is required. Browser sign-in
and unrelated connector access do not supply this broker's Calendar API grant.
Never paste access tokens or client secrets into chat, command arguments or logs.

## 1. Establish account access without a write

Use a dedicated test account and a Google OAuth client with the Calendar API
enabled. For a desktop test use Google's system-browser authorization-code flow
with PKCE S256, an unpredictable state value and a loopback redirect. Let the
account owner complete Google consent. Prefer a maintained OAuth client library.
Do not extract browser cookies or repurpose another application's client secrets.

For this preflight, request `https://www.googleapis.com/auth/calendar.events.readonly`.
The API request is fixed to:

```http
GET https://www.googleapis.com/calendar/v3/calendars/primary/events?maxResults=1&fields=kind
Authorization: Bearer <obtained outside chat>
```

The projection requests the collection kind, not event titles, attendees or
content. The token source must supply an owner-only regular file. From an
installed broker or a checkout with `src` on Python's import path, run:

```sh
python -m credential_broker.calendar_preflight --token-file /absolute/protected/access-token
```

The CLI prints only PASS/FAIL/ERROR, HTTP status when available, and explicit
flags that this is not a delegated-flow proof and performs no provider write.
It disables environment proxies and redirects, bounds response size, and does
not output provider error bodies. It does not delete or revoke the input token.
Do not mistake a successful access preflight for cryptographic authorization of
an operation through the Gate. An expired token, unavailable API or absent scope
is an access failure, not evidence against the delegation protocol.

## 2. Prove the existing delegated operation against Google

After read access succeeds, review a concrete test event in the selected account:
unique caller-supplied event ID, title, UTC start/end, primary calendar, no
attendees, no recurrence and `sendUpdates=none`. The existing profile performs a
write; the read-only token is intentionally insufficient. Obtain the narrowest
appropriate writable scope, such as `calendar.events.owned` for an owned calendar,
through the account owner's consent.

Wire `CalendarExecutor` to the real `CalendarCallService` and an account-specific
credential source. Use the signed request/review/approval/callback/exchange flow
from [the integration contract](DELEGATED_AUTHORIZATION.md), not merely the older
calendar-approve CLI or an unrelated connector. Pin the service and owner keys
independently. Record the exact request commitment before approval.

Attempt an altered operation first and verify zero provider dispatches. Execute
the exact approved call once; verify the signed result and custody receipt.
Attempt replay after restart and verify no additional dispatch. Independently
read back the explicit event ID from Google and compare the approved fields.
If dispatch has an uncertain outcome, reconcile by ID instead of blindly retrying.
Deletion of the test event is a separate authorized operation; the current Gate
profile does not implement event deletion.

## 3. Retain a bounded evidence record

Retain source revision, dependency versions, UTC run time, request commitment,
HTTP status, verified receipt, replay verdict, provider dispatch count and custody
state. Keep account identifiers and the reviewed event in protected local storage.
Do not retain the provider token, authorization code, refresh token or private keys
in the report. Explicitly distinguish simulated transport, live read access and
live delegated write results. Do not label the run PASS if any required stage is
unperformed. Local key destruction does not revoke the Google grant or erase
source-owned copies; record upstream revocation separately if performed.

References: [scopes](https://developers.google.com/workspace/calendar/api/auth),
[events.list](https://developers.google.com/workspace/calendar/api/v3/reference/events/list),
[desktop OAuth](https://developers.google.com/identity/protocols/oauth2/native-app).
