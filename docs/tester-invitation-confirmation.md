# Delayed Apple invitation confirmation

Apple can accept an individual invitation before its app-scoped tester query changes
from NOT_INVITED to INVITED. Group membership alone is not confirmation. Welcome
instructions remain suppressed until INVITED, ACCEPTED or INSTALLED is confirmed.

The provider checks immediately, then after 1, 2 and 4 seconds (seven seconds of
backoff; each HTTP request retains its existing 15-second timeout). Only GET status
requests are repeated. Definite Apple refusals remain hard failures. Ambiguous
transport/response failures after a possible write are pending, never a resend signal.

Migration 015 adds durable confirmation scheduling and safe response metadata.
The tester reference and pending state are checkpointed before notification work.
If tester creation loses its response, reconciliation searches the exact email and
never recreates the tester. Existing legacy `apple_invitation_pending` rows are
scheduled for this same read-only reconciliation.

The server worker checks due workflows every minute and at startup, up to 20 times.
It uses the existing per-email PostgreSQL advisory lock, rechecks current access and
platform enablement, and never creates identities, changes memberships or sends
Apple invitations. After the ceiling, Check confirmation performs another read-only
check. A sleeping free staging instance resumes due work on wake; wall-clock delivery
is not guaranteed while Render has suspended it.

After confirmation, the existing welcome-email path uses the same saved content and
Resend idempotency key. Concurrent workers, manual retries, restarts and uncertain
email delivery retain the existing duplication protections and 23-hour safety cutoff.
The dashboard labels pending confirmation separately from failure and polls its
read-only list while pending rows are visible. No general invitation policy changes.

Diagnostics retain fixed endpoint labels, GET/POST, HTTP status, timestamp, response/
transport category and allowlisted Apple error codes. The last eight write outcomes
and 32 reads are retained. No request/response bodies, authorization headers, JWTs,
private keys, raw error prose or email query URLs are recorded or returned to the UI.

Validation uses mocked Apple/Resend delivery and an isolated loopback PostgreSQL
schema. `pending@example.test` in the local dashboard harness demonstrates automatic
confirmation without any real email or Apple calls.
