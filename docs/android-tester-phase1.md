# Android tester invitations — Phase 1 local candidate

Implemented and locally validated on 2026-09-12. **Not deployed. No live invitation was sent.**

## Authority and scope

Production candidate base: `9891aacbf599fe244c2513c1180fb5bee3cad6f8`.
Dashboard candidate base: `f88c5f560928bc13922a2e775a2592e2214d1835`.
Both candidates are uncommitted. The existing dirty backend checkout and Android release sources were not edited.

Production owns Android approved-person records, invitation/eligibility/delivery state, OTPs, signing, entitlement checks, revocation and audit. The existing staging tester dashboard forwards only Android admin list/actions to the fixed production `/internal/android-tester-admin` endpoint. It uses a separate server-held, Android-admin-only credential; it never sends that credential to the browser. Production does not read a staging database, accept a staging OTP or trust a staging JWT signing key. No OTP/session synchronization, Google Group automation or Play list API was introduced.

iOS continues using the staging Partner service, records, TestFlight enrollment, Apple confirmation polling, email template, OTP and resend/revoke flows. With Android forwarding enabled, the legacy staging Android invitation endpoint rejects Android actions before provisioning, enrollment or email. Existing iOS records are not migrated.

## Production auth and schema

- `013_partner_access.sql`: reviewed organizations, people, HMAC challenge storage, audit and durable rate buckets.
- `014_tester_invitations.sql`: reviewed per-person/platform invitation and durable delivery/idempotency state.
- `015_android_tester_eligibility.sql`: production-specific manual Play state (`not_confirmed`, `confirmed`, `removed`), confirmation actor/time and one empty default tester organization. No people, OTPs or sessions are seeded.
- Baseline migrations 001–012 are byte-identical. Production 015 is **not** staging's Apple-confirmation migration 015. Never apply this candidate to the Partner staging database.
- `scripts/preflight_android_testers.js` runs a read-only ledger/schema check. It requires baseline 012, uses the normal immutable migration guard, rejects incompatible or untracked tester schema, and reports pending migrations without modifying the database. The full 001–012 → 015 upgrade and restart were tested on an empty local PostgreSQL database. The hosted production ledger must still be reconfirmed before a separately authorized deployment.

The existing production JWT signer now retains the server-generated `auth_method`, `partner_invite_id` and `platform` claims; `sub`/`uid`, issuer, audience, algorithm and expiration remain controlled by the signer. Both existing verification paths attach only verified claims. Ordinary Google/Apple signer calls and guest behavior remain unchanged.

Preview enforcement remains optional (`required:false`). Verified preview requests recheck current production entitlements, including feature flags. Revoked/expired access is denied on the next server request; Android retains the existing 60-second refresh/lease contract. Account deletion invokes the reviewed tester-record deletion for the authenticated preview identity. Ordinary account deletion bypasses this helper. Production ships no staging reviewer override and does not instantiate a development mailbox.

## Invitation workflow

1. Select Android and enter **Google Play email**. Helper: “Use the email connected to your Google Play account. This may be different from your work email.” Non-Gmail addresses are valid; no Google account lookup is attempted.
2. **Prepare Android invitation** provisions/reuses production access. It preserves existing identity, features and expiry. New access defaults to seven days, Flights/Hotels/Combined Trip on and Checkout off. It sends no email and does not confirm Play eligibility.
3. Add the exact email manually to a Play Console individual tester list selected for Internal Testing, then use **Confirm Play eligibility**. This records a manual attestation and sends no email.
4. Use **Send Android invitation** explicitly. Both API and UI reject sending unless Android access is active and manual Play eligibility is confirmed.
5. Zippi access, manual Play state and welcome delivery are displayed independently. Revoke/Disable changes only Zippi preview access; manual Play removal changes only its dashboard record. Neither uninstalls the app or edits Play Console.

Welcome subject: **You're invited to preview Zippi on Android**.
Branded steps: open the Play invitation with the email's Google Account; join/install; open Account → Partner Preview; enter the invited email and Continue; enter the six-digit verification code subsequently sent by email.
CTA **Join Android Test**: https://play.google.com/apps/internaltest/4701051442738255142
Support remains support@heyzippi.com. The welcome contains no OTP or password. Existing branded chrome/logo and inline image delivery are reused. Browser rendering was reviewed; actual mailbox-client rendering remains a live QA check.

OTP behavior: random six digits, ten-minute expiry, five verification attempts, 60-second resend cooldown, keyed digest only in challenge storage, consumed after success, neutral unknown-address response, durable email/IP/device rate limits. Welcome resend is separate: five-minute cooldown, durable idempotency key/payload, concurrent-send lock, repeated initial Send is a no-op once sent. Failed/uncertain delivery retains identity, eligibility and idempotency across restart. A fresh explicit resend key is created only after successful prior delivery; uncertainty beyond the existing safe 23-hour deduplication window requires provider review instead of an automatic duplicate. No automatic mail retry or fallback provider was added.

## Configuration required before deployment

No live configuration was changed and no bridge credential was created.

Production:
- Existing `DATABASE_URL`, production `JWT_SECRET`/issuer/audience and admin session configuration stay production-owned. Never copy staging signing secrets or auth state.
- `ZIPPI_ANDROID_TESTER_AUTH_ENABLED=true` enables the optional Android OTP routes. Default is off.
- `RESEND_API_KEY` and `ZIPPI_PARTNER_EMAIL_FROM` must identify an authorized server-side mail account and verified branded sender. Values must stay in server secrets; not source, browser or mobile configuration.
- `ZIPPI_ANDROID_TESTER_BRIDGE_ENABLED=true` enables only the private Android administration router. Default off.
- `ZIPPI_ANDROID_TESTER_BRIDGE_SECRET`: separately provisioned high-entropy server secret (accepted length 32–512 characters), shared only with the staging server. Not a JWT key or OTP secret. Missing/invalid configuration fails closed.
- Optional `ZIPPI_ANDROID_TESTER_ORGANIZATION_ID` selects an existing approved production organization; otherwise the migration's empty Android Internal Testers organization is used.
- Optional `ZIPPI_ANDROID_TESTER_DURATION_DAYS`: 3, 7 or 14, default 7. Browser cannot override organization, features or duration.

Staging dashboard:
- Existing signed admin session and iOS configuration unchanged.
- `ZIPPI_ANDROID_TESTER_REMOTE_ENABLED=true` and the same dedicated `ZIPPI_ANDROID_TESTER_BRIDGE_SECRET` enable Android forwarding.
- Destination is fixed in code to the existing production host; no caller-controlled host, redirect following or arbitrary proxy is permitted. Forwarding is bounded to 20 seconds, with no automatic mutation retry/fallback into staging.

Before enabling: reconfirm both deployed baselines, run production read-only schema preflight, apply the production-only migrations through the normal guarded migration command, configure production auth/mail/bridge, deploy the staging UI companion without changing its migrations, and verify optional auth remains optional.

Rollback: disable the new auth/bridge/forwarding flags to stop preview administration and deny preview sessions while preserving ordinary guest/auth behavior. Keep additive tester tables and durable invitation records. An old binary lacking migrations 013–015 will fail the immutable-ledger guard after migration; a rollback build must retain those exact migration files/checksums. Do not bypass the guard or drop records to roll back. No mobile rollback is required.

## Validation

All providers and email delivery were mocked; only a new empty loopback PostgreSQL database was used. Synthetic `heyzippi.test` addresses were used. No hosted tester/auth database or real inbox was changed.

- Production focused auth/service/OTP/migration/HTTP/template tests: **32/32**.
- Dashboard forwarding plus existing invitation/iOS-focused tests: **46/46**.
- Full production candidate backend suite: **228/228**, zero skipped/failed.
- Full dashboard/iOS candidate backend suite: **353/353**, zero skipped/failed.
- Syntax: all changed JavaScript files passed (`20` production, `9` dashboard).
- Migration upgrade/restart, mismatched staging-ledger rejection and read-only preflight passed; all prior migration files unchanged, both dependency manifests unchanged.
- Actual production signer/hydration/verification functions executed in HTTP tests. Tested version-10 wire payload, private bridge → production records → OTP → claims → entitlement → revoke, invalid staging-signed JWT rejection, and account deletion cleanup.
- Browser: original iOS form; Android label/helper; prepare without mail; Send disabled before confirmation; cancel/confirm dialog; confirmation without mail; explicit single welcome; disabled resend during cooldown; independent revoke; independent manual Play removal; switch back to unchanged iOS form and separate local iOS action; branded email/opt-in preview. Fixture totals: one Android welcome, zero OTPs from admin invitation actions, one independent iOS action. Backend OTP delivery was exercised separately with the mock mailbox.
- Final browser review fixed Android panel padding and disabled-action visibility. No iOS template or auth source changed in the dashboard candidate.
- `git diff --check` passed in both candidates.
- Android release: all **595/595** recorded source hashes still match; version-10 AAB SHA-256 remains `f98946fc9492860c29c33746a535b817b4891391e1eebb629532ac536a5c2a07`.

## Readiness and limits

Implementation is ready for separate deployment/configuration authorization. It is **not ready to send the first live invitation yet**, because these candidates are uncommitted/undeployed and production mail/bridge/schema preflight and live controlled QA remain outstanding.

Version 1.0.7 (10) can be used unchanged for this optional OTP flow. Its Work email label and outdated preview feature-summary wording remain deferred app-copy items. No new AAB, Samsung install or Play rollout is needed for this backend enablement.

After deployment, choose a designated Zippi-controlled QA mailbox, manually confirm its Play-list eligibility, then authorize one controlled welcome and real version-10 OTP/login/revoke smoke. Local HTTP compatibility and browser tests are not a claim of live email delivery or a fresh physical-device login.

## Exact candidate files

### Production candidate (29 files)

- `admin/public/android-testers.css`
- `admin/public/android-testers.js`
- `admin/public/partner-access.css`
- `admin/public/partner-access.html`
- `admin/public/tester-invitations.css`
- `docs/android-tester-phase1.md`
- `lib/adminDashboard.js`
- `lib/androidTesterEmail.js`
- `lib/androidTesterPreflight.js`
- `lib/androidTesterRemote.js`
- `lib/androidTesterRoutes.js`
- `lib/androidTesterRuntime.js`
- `lib/androidTesterService.js`
- `lib/emailTemplates/partnerWelcome.html`
- `lib/partnerAccess.js`
- `lib/partnerAccessResendMail.js`
- `lib/partnerAccessRoutes.js`
- `lib/partnerEmailBranding.js`
- `lib/partnerVerificationEmail.js`
- `migrations/013_partner_access.sql`
- `migrations/014_tester_invitations.sql`
- `migrations/015_android_tester_eligibility.sql`
- `scripts/preflight_android_testers.js`
- `server.js`
- `test-support/androidTesterFixture.js`
- `test/androidTesterEmail.test.js`
- `test/androidTesterHttp.test.js`
- `test/androidTesterMigration.test.js`
- `test/androidTesterService.test.js`

### Dashboard candidate (12 files)

- `admin/public/android-testers.css`
- `admin/public/android-testers.js`
- `admin/public/partner-access.html`
- `admin/public/tester-invitations.js`
- `docs/android-tester-phase1.md`
- `lib/adminDashboard.js`
- `lib/androidTesterRemote.js`
- `lib/androidTesterRoutes.js`
- `lib/testerInvitations.js`
- `server.js`
- `test/androidTesterDashboard.test.js`
- `test/testerInvitations.test.js`
