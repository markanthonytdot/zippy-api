# Dashboard tester invitations

## Apple API activation — September 10, 2026

The user supplied the App Manager Team Key named **Zippi TestFlight Invites**.
Its issuer, key identifier and private key are stored only in the isolated
staging Render environment using the three existing `ZIPPI_TESTER_APPLE_*`
credential variables. No credential values are recorded here or in the client.

Live read-only authentication returned HTTP 200 for **Hey Zippi / 6757395108 /
com.heyzippi.zippi**, the external groups, builds and the designated QA tester.
Build **1.3.1 (12)** is processed (`VALID`), unexpired and beta-approved. With
explicit user authorization, it was added to the existing **Beta Testers** group
after disabling automatic notifications for that build. The association returned
HTTP 204 and was confirmed by a fresh group-build read. Build 11, the Mark group,
existing public links and App Store submission/release metadata were not changed.

Two live API compatibility details are covered by regression tests:

- Apple's general tester lookup and individual tester resource can return a null
  state. Status reads now use the documented `filter[id]` plus `filter[apps]`
  query and require the exact returned tester. Global email lookup is retained
  for identity reuse, so an existing tester is not duplicated.
- Switching automatic notifications off changes an approved build's external
  state from `IN_BETA_TESTING` to `BETA_APPROVED`. Both are valid for invitation
  preflight; processing, review-pending, rejected and expired states fail closed.
  Individual invitations use the supported tester-invitation endpoint. No bulk
  build notification is sent by this adapter.

The production adapter's live read-only preflight and app-scoped status refresh
passed. The user designated one controlled QA recipient with one-day access;
the final hosted invitation outcome is reported separately after deployment.
Android remains disabled until the intended Android build is uploaded and verified.

Apple references: [tester queries](https://developer.apple.com/documentation/appstoreconnectapi/get-v1-betatesters),
[build statuses](https://developer.apple.com/help/app-store-connect/reference/app-uploads/app-build-statuses/),
[build notification setting](https://developer.apple.com/documentation/appstoreconnectapi/patch-v1-buildbetadetails-_id_),
[group-build assignment](https://developer.apple.com/documentation/appstoreconnectapi/post-v1-betagroups-_id_-relationships-builds).

## Audit and current external readiness — September 10, 2026

The following records the initial audit, before the Apple activation above.

This feature extends the existing Express admin dashboard at
`https://zippi-partner-staging.onrender.com/admin/partner-access`. It uses the
existing signed, HttpOnly/Secure/SameSite admin session, Partner Access database
and Resend HTTPS adapter. It introduces no mobile code or second login system.

Audited backend baseline: `66bd1f0e3d959eb26e6beb3e1ce0883511633eb6`, branch
`codex/partner-preview-staging`. Staging is Render service
`srv-dagq12ht0dsc73a7dm40`, with separate `zippi-partner-staging-db`
(`dpg-dagpide1egvs73au4k20-a`). Production and shared databases are excluded.
Existing manual deployment runs `npm run migrate && node server.js`.

### Apple

- App **Hey Zippi**, app ID `6757395108`, bundle `com.heyzippi.zippi`.
- Existing external group **Beta Testers**, ID
  `a81451ab-a35e-4bf6-b11b-521a6e3df853`: 16 testers, **0 builds**, and Apple's
  “No Compatible Build” notice. Its existing public link was observed, not created
  or changed. The separate **Mark** group is not targeted.
- Users and Access → Integrations → App Store Connect API shows **Request Access**.
  API access is not enabled; issuer ID/key ID/private key are not available there.
  The staging environment has no Apple tester API credential variables.
- Build 1.3.1 (12) was last observed processing. No build, group-build relationship,
  review, release, public link, metadata or automatic-distribution setting was changed.
- Live invitation verification is blocked by both API setup and zero testable group
  builds. Attaching/releasing a build is outside this feature's authorization.

### Android

- User confirmed the correct Google account is `support@heyzippi.com`. The initially
  offered unrelated account was not used. No password/MFA code was entered by the agent.
- Authenticated Play Console confirms **Zippi / com.heyzippi.app**, app ID
  `4973918216456348015`, developer `7103082433699474199`.
- Open testing is active, unlimited testers, 177 countries/regions. Current release
  **1.0.7 (9)**, May 6. Feedback address: `support@heyzippi.com`.
- Confirmed web opt-in link: `https://play.google.com/apps/testing/com.heyzippi.app`.
  Android install link: `https://play.google.com/store/apps/details?id=com.heyzippi.app`.
- The other `com.heyzippi.zippi` listing is a draft and is not used.
- The user confirms the intended latest Android binary has **not** been uploaded.
  The Android invitation adapter stays disabled until the intended build and its
  Partner Access environment are physically verified. No Android binary was changed.
- Open testing does not require an admin email list, Google Group, service account
  or Developer API credential. Users must opt in with their own Google account;
  there is no supported per-email enrollment or installation-status API for this flow.
  The dashboard therefore says **Opt-in required**, never falsely **Enrolled**.

### Email / existing access

Resend remains selected by `ZIPPI_PARTNER_MAIL_ADAPTER=resend`, using existing
`RESEND_API_KEY` and `ZIPPI_PARTNER_EMAIL_FROM`. The existing verified sender is
`Zippi Partner Preview <preview@heyzippi.com>`. OTP subject/content, hashed storage,
cooldown, expiry, one-time use and rate limits are unchanged. SMTP OTP support and
the deterministic local OTP adapter remain intact; the welcome workflow requires
the existing Resend adapter's `sendInstructions` method. No SMTP fallback.

The existing person is keyed by normalized email. An invitation authorizes one
platform and unions it with existing platforms. New people receive seven days by
default, Flights/Hotels/Combined Trip enabled and Checkout disabled. Existing
organization, expiry and feature flags are preserved. Revoked, disabled, scheduled
or expired people require an explicit existing Restore/Extend action; inviting
again does not silently undo these controls. The normal OTP verification is still
required in the app. A platform invitation does not mint a preview token.

## Workflow and recovery

Admin enters **Email → iOS OR Android → Invite to Zippi**. No Both option.

1. Existing admin middleware and same-origin JSON guard authorize the request.
2. Normalize email and validate the platform, policy and database-backed rate limit.
3. Acquire a PostgreSQL session advisory lock for the email; concurrent attempts
   return a recoverable `invitation_in_progress`. No database transaction spans a
   provider HTTP call. The existing access service reuses this connection to avoid
   pool starvation, and its existing email transaction lock protects shared identity.
4. Create/reuse Partner Access, then the unique `(person_id, platform)` workflow.
5. Apple: validate the configured external group belongs to the exact Zippi app,
   with an unexpired `IN_BETA_TESTING` or `BETA_APPROVED` build. Find existing tester by exact normalized
   email, create only if absent, ensure existing group membership, then re-read.
   Automatic notifications are not duplicated. When notification is disabled and
   Apple reports `NOT_INVITED`, use the supported invitation endpoint with a durable
   notification cooldown. Responses retain Apple's actual tester states:
   `NOT_INVITED`, `INVITED`, `ACCEPTED`, `INSTALLED`, `REVOKED`. These are Apple's
   tester-resource observations, not fabricated per-build installation telemetry.
6. Android: validate the audited open-testing configuration and verified-build flag,
   then prepare the existing opt-in path. Google enrollment is completed by the tester.
7. Persist platform confirmation before sending welcome instructions. Recheck active
   preview access first. Welcome subject: **You're invited to preview Zippi**.
   Instructions cover platform install, same-email preview verification and feedback.
8. Store provider acceptance separately from inbox delivery; **Sent (provider accepted)**
   is not a claim that the email was delivered or opened.
9. Record actor, invitation/person ID, platform, action, safe result and timestamp in
   the existing Partner Access audit table. No extra email is placed in audit metadata.

Repeated Invite returns the existing workflow without sending anything. Use **Retry**
for partial failures. Successful enrollment is never repeated to retry a welcome
email. **Resend instructions**, **Refresh Apple status** and **Resend TestFlight invite**
are available as appropriate, with a five-minute cooldown. Actions allow 30 per admin
per hour and 150 globally per hour, stored in the existing HMAC-keyed rate-limit table.

Resend keys and the exact non-PII template payload are durable before delivery.
Retry uses the same key/payload. An explicit resend after confirmed acceptance gets
a new key. Unconfirmed deliveries older than 23 hours require checking Resend;
the workflow will not blindly resend outside its 24-hour idempotency guarantee.
After checking Resend, reconcile that workflow's delivery status server-side before
retrying. There is deliberately no “ignore uncertainty and send again” browser control.

Platform errors are allowlisted; raw HTTP responses, keys, JWTs and stack traces never
reach the dashboard or application logs. Incomplete Apple collection responses fail
closed (`apple_result_limit`) rather than assume absence and create duplicates.
No universal invitation API proxy is exposed. There are no build/version/review or
release mutation methods in the Apple adapter.

## Database and routes

Additive migration **014_tester_invitations.sql** adds one table, referencing the
existing `partner_people` row with `ON DELETE CASCADE`, one unique constraint and
an updated-time index. No existing rows, checksums or entitlements are rewritten.
Email remains only in `partner_people`; no OTP or credential is added to the table.
The compact dashboard shows the 200 most recently updated workflows; older records
remain durable. This is an operational list, not a bulk-invitation/CRM interface.

All new routes are behind the existing `/admin` session middleware:

- `GET /admin/api/tester-invitations`: safe readiness and recent statuses.
- `POST /admin/api/tester-invitations`: only `email` and `platform` accepted.
- `POST /admin/api/tester-invitations/:id/retry`
- `POST /admin/api/tester-invitations/:id/resend`
- `POST /admin/api/tester-invitations/:id/apple-resend`
- `POST /admin/api/tester-invitations/:id/refresh`

## One-time staging setup

Keep invitations disabled until setup is complete. Store secrets directly in Render
environment/secret storage, never source, chat, frontend fields or documentation.

| Variable | Purpose |
| --- | --- |
| `ZIPPI_TESTER_INVITES_ENABLED` | `true` only to enable admin workflows; defaults off |
| `ZIPPI_TESTER_ORGANIZATION_ID` | UUID of an existing active Partner Access tester organization |
| `ZIPPI_TESTER_DURATION_DAYS` | Optional new-person duration: 3, 7 (default), or 14 |
| `ZIPPI_TESTER_APPLE_APP_ID` | `6757395108` (only this app is accepted) |
| `ZIPPI_TESTER_APPLE_GROUP_ID` | Audited external Beta Testers group UUID above |
| `ZIPPI_TESTER_APPLE_ISSUER_ID` | Team API issuer, available after Apple enables API access |
| `ZIPPI_TESTER_APPLE_KEY_ID` | Dedicated tester-management API key ID |
| `ZIPPI_TESTER_APPLE_PRIVATE_KEY` | Secret: multiline Apple .p8 PEM, stored only in Render |
| `ZIPPI_TESTER_ANDROID_MODE` | `open_testing` for the existing channel |
| `ZIPPI_TESTER_ANDROID_PREVIEW_BUILD_VERIFIED` | `true` only after intended Play build and matching staging access are verified |

Reuse existing `ZIPPI_PARTNER_MAIL_ADAPTER`, `RESEND_API_KEY`,
`ZIPPI_PARTNER_EMAIL_FROM`, admin/session secrets, JWT secret and isolated database.
No Google service account is needed for this open-testing model. Do not provision one.

Apple Account Holder must first complete **Users and Access → Integrations → App
Store Connect API → Request Access**. After approval, create a dedicated key with
the least role capable of managing external testers (Marketing). Do not use an
Account Holder/Admin private key. Apple team keys apply across apps; the backend
additionally restricts the app and group and exposes tester operations only. Keep
the .p8 in secure storage and enter it directly in Render. Keys cannot be re-downloaded;
if the private key is unavailable, generate a replacement and revoke the unused key.

The configured group must already have an intentionally distributed compatible
external-testing build. Adding it requires separate distribution authorization and
is not part of invitation setup. Do not work around zero builds by editing build 11/12.

Real QA is limited to the already designated `s.mark@me.com` after both provider and
build readiness are satisfied. `support@heyzippi.com` identifies console login and
support; it was not implicitly selected as the invitation recipient. No customer list
or real partner is authorized for bulk invitation.

## Validation / local acceptance

Full suite with loopback PostgreSQL: **217 passed, zero failures/skips**. Includes
existing OTP/reviewer/admin/rate-limit/lifecycle tests and 37 new provider/workflow
tests. Test databases use random schemas and are dropped afterward. No hosted
database or real provider is used by automated tests.

```sh
PARTNER_TEST_DATABASE_URL=postgres://marks@127.0.0.1:55432/postgres npm test
git diff --check
```

JavaScript syntax checks pass for server, new modules and browser script. There is
no separate lint, TypeScript or compilation script in this CommonJS backend.

Browser acceptance uses `scripts/run_tester_invitation_dev.js` with loopback DB,
a locally chosen `TESTER_DEV_ADMIN_SECRET`, an ephemeral schema and only
`@example.test` recipients. Every provider is mocked. Verified: signed admin login,
iOS success, repeated iOS without duplication, same-email Android with one shared
person, accurate opt-in state, platform failure/no welcome, cooldown-disabled retry
buttons and visual layout. No real invitation or welcome was sent.

Live Apple: configuration blockers confirmed, invitation not attempted.
Live Android: exact open-testing track/link confirmed read-only; old binary, no
enrollment attempted. Current intended Android build remains a separate task.

## Deployment

Verified deployed runtime: `9e384f3069777c0d8f3a1863afca07558a718f97`, Render deploy
`dep-dahgt415efls73bsr490`. `/version` confirms this SHA. `/health`, `/health/db`
and `/partner-access/config` return 200; Partner Access remains required and all
reported checkout/booking controls remain disabled. Anonymous admin invitation
requests return 401. The authenticated dashboard loads the new panel and the
two existing active QA/reviewer records. No real invitation or welcome email was sent.

Created the empty **Zippi Testers** organization
`ff752a41-2b3b-4558-8f6e-4336abbc88d2` and configured the seven non-secret tester
settings in isolated staging. Seven-day policy, exact Apple app/group IDs and
Android open-testing mode are saved. Both the global invitation enable flag and
Android verified-build flag are explicitly `false`. No existing person's access
or existing secret was changed. The dashboard accurately shows setup pending.

The follow-up local harness login redirect and this deployment record do not alter
the deployed runtime. The harness's default post-login route now goes directly to
Partner Access; its fixture schema intentionally excludes the unrelated booking
overview. Direct login landing was verified in the browser.

Deploy this additive dashboard/backend change only to isolated staging, from the
tested `codex/partner-preview-staging` commit, using the normal migration command.
Keep the feature's enable flag unset/off while credentials and builds are missing.
Then check `/health`, `/health/db`, `/partner-access/config`, unauthenticated admin
rejection, and authenticated dashboard readiness. No production or mobile release
is included. See the task report for the actual deployed revision and observations.

## Changed files

- `admin/public/partner-access.html`, `admin/public/partner-access.js`: invitation
  section and refresh existing people after successful workflow activity.
- `admin/public/tester-invitations.js`, `admin/public/tester-invitations.css`: form,
  readiness, status list and throttled action presentation.
- `lib/adminDashboard.js`, `server.js`: existing authenticated router/service wiring.
- `lib/partnerAccess.js`: shared-identity authorization helper and reusable DB connection.
- `lib/partnerAccessResendMail.js`: reusable HTTPS welcome delivery with idempotency.
- `lib/testerInvitations.js`: durable workflow, projections, locking, rate limits and audit.
- `lib/testerInvitationProviders.js`: restricted Apple API and actual Android open-testing model.
- `lib/testerInvitationRoutes.js`, `lib/testerInvitationEmail.js`: protected API and templates.
- `migrations/014_tester_invitations.sql`: additive workflow table/index.
- `test/testerInvitations.test.js`, `test/testerInvitationProviders.test.js`: deterministic regression coverage.
- `scripts/run_tester_invitation_dev.js`: isolated browser acceptance harness.
- `docs/tester-invitations.md`: audit, setup, operation, validation and deployment record.

## Provider references

- [Apple beta testers](https://developer.apple.com/documentation/appstoreconnectapi/beta-testers)
- [Apple invitation semantics](https://developer.apple.com/documentation/appstoreconnectapi/beta-tester-invitations)
- [Apple tester states](https://developer.apple.com/documentation/appstoreconnectapi/betatesterstate)
- [Apple API access and keys](https://developer.apple.com/help/app-store-connect/get-started/app-store-connect-api)
- [Google testing setup](https://support.google.com/googleplay/android-developer/answer/9845334)
- [Google edits.testers schema](https://developers.google.com/android-publisher/api-ref/rest/v3/edits.testers)
- [Resend idempotency](https://resend.com/docs/dashboard/emails/idempotency-keys)
