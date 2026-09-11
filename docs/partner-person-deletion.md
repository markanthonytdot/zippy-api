# Partner Preview Delete Person

Delete in Manage existing people removes the entire Partner Preview person, across
all entitled platforms and stored platform invitations. A read-only preflight
supplies the exact person ID, normalized email, organization and union of platforms.
The dialog names that email and every platform, defaults focus to Cancel, and
requires explicit Delete person confirmation. The server rechecks the entire target
under locks and rejects changed/missing confirmation. Revoke/Restore remain separate.

## Schema and retention

The schema has no link from partner_people to regular accounts or bookings.
Deleting partner_people removes the entitlement, organization membership and email.
Foreign-key cascades remove partner_verifications (hashed OTPs) and tester_invitations
(all platform status, provider IDs, retry state, welcome payload, delivery key and
message state). Prior per-person partner_access_audit rows are removed. One
person_deleted security event remains, containing the old opaque person UUID,
platforms, admin actor, timestamp, scope, result and externalTestersChanged=false;
its person FK becomes null. It contains no email, OTP, token or provider credential.

Organizations and their other members, regular app accounts, bookings and provider
records are untouched. HMAC-only abuse/rate-limit buckets retain their existing TTLs;
deleting a person does not reset abuse controls. No database migration is required.

## Security and concurrency

Only the existing signed-admin router exposes GET /people/:id/deletion and
POST /people/:id/delete. Writes require same-origin JSON. Delete is limited using
the existing durable HMAC rate limiter (20 per admin/hour, 60 total/10 minutes).
The transaction acquires the invitation advisory lock before the email and row
locks, refusing in-flight delivery with invitation_in_progress. Invitation retries
recheck their original row after locking so a stale retry cannot recreate a deleted
person. Repeat deletion returns person_not_found (404). A subsequent deliberate new
Invite creates a new UUID and fresh invitation/delivery state. Old JWTs reference
the deleted UUID and cannot authorize the new person.

There are no Apple/Google mutation or mail calls in deletion. A person whose Apple
tester still exists can be deleted locally; deleting that external tester is a
separate explicitly authorized operation.

## Validation

321 backend tests passed using isolated local PostgreSQL schemas and mocked external
providers. Coverage includes correct-target confirmation, admin/origin protections,
multi-platform deletion including a stored platform no longer entitled, OTP and
invitation cascades, audit privacy, organization/other-person preservation, stale
JWT denial, repeated deletion, fresh reinvite, in-flight lock refusal, stale-retry
race and durable rate limits. Unexpected exceptions remain generic.

Local real-browser acceptance: Invite fixture, open named/platform confirmation,
Cancel (row preserved), Delete (row removed; organization preserved), then fresh
fixture Invite (new identity/time, successful mocked provider and welcome). No real
email was sent. git diff --check passed.

Live rollout: deploy the exact tested staging commit; verify support@heyzippi.com
has one identity and iOS invitation in Zippi Testers with stored INVITED status,
and independently confirm Apple has no tester with that email. Only then use the
new dashboard Delete. Stop before any live reinvitation.
