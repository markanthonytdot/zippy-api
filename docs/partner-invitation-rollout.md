# Partner invitation rollout — September 10, 2026

Eligibility interpretation updated: see [Apple invitation candidates](apple-invitation-candidates.md).

## Dashboard

The top **Invite to Zippi** form is the only person-onboarding workflow: email,
optional organization from existing active organizations, iOS, Invite to Zippi.
An omitted organization retains an existing person's organization or uses the
configured default for a new person. Explicit selection validates the existing
organization and email-domain rules, records that organization on the same person,
and preserves customized features and expiry. No second organization model exists.

The lower **Manage existing people** section filters by organization and combines
access, expiry, permissions, TestFlight state, welcome status and retry/resend
controls. It has no Add Person action. The existing Add organization dialog is
reused and refreshes both selectors. Existing unassigned people, if any, receive
a No organization filter. Access editing, extend, revoke and restore stay available.

## Provider separation and staged activation

- Primary group: **Zippi Partners**, `b13afcde-cbb2-44cf-9518-5d6ce9724731`.
- Build: **1.3.1 (13)**, already processed, approved and `IN_BETA_TESTING`.
- Created the empty external group and assigned this existing build. Live adapter
  preflight passed with automatic notifications off. No activation or bulk
  notification was required or called. No legacy group was changed.
- Keep `ZIPPI_TESTER_APPLE_GROUP_ID` set to that partner group and
  `ZIPPI_TESTER_APPLE_GROUP_NAME=Zippi Partners`.
- Enable `ZIPPI_TESTER_INVITES_ENABLED=true` only after deploying the separate
  QA-provider routing. Existing signed admin cookie and same-origin JSON guards
  protect every invitation action. Credentials remain server-side Render secrets.
- Keep `ZIPPI_TESTER_QA_ENABLED=true`. The designated `s.mark@mac.com` identity
  always uses the separately constructed **Zippi Dashboard QA** provider with its
  fixed group ID/name and existing staging/app/admin checks. The primary group
  configuration cannot move that QA account into Partners.
- Android stays disabled with
  `ZIPPI_TESTER_ANDROID_PREVIEW_BUILD_VERIFIED=false`, including direct API requests.
- New-person defaults remain seven days, iOS, Flights/Hotels/Combined Trip on,
  Checkout off. Existing expiry and custom feature permissions are preserved.
- Apple enrollment checks the exact app/group and an unexpired installable build,
  reuses exact existing testers and memberships, and uses only individual invitation
  operations when needed. It never changes builds or calls bulk Notify Testers.
- Repeated Invite reads the durable workflow. Explicit retry/resend respects existing
  locks, rate limits, cooldowns and Resend idempotency. Partial failure remains visible.

## Validation

Clean isolated backend source: 230 tests passed, zero failures or skips, using an
isolated loopback PostgreSQL database and mocked Apple/Resend delivery. Includes
organization selection/domain validation, existing-user preservation, QA routing,
Android rejection, idempotency, authorization, OTP/reviewer security and Apple
app/group/build checks. JavaScript syntax and `git diff --check` pass.

Local browser acceptance uses `scripts/run_tester_invitation_dev.js`, an ephemeral
schema and only `@example.test` addresses. It exercises the actual signed-admin
form, existing organization creation, selected organization assignment, filtered
management rows, repeated Invite without duplicates, permission editing, one-day
extension, revoke and restore with mocked external delivery. Android in the
harness is disabled to match staging.

The final fresh-person Apple/Resend test still requires a new user-controlled email.
Previously documented QA addresses are already used; no airline contact or fresh
real person has been invited during this rollout. Deployment/hosted acceptance is
reported separately after completion. Mobile binaries and production are unchanged.
