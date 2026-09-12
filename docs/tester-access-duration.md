# Partner Preview access duration — presets and Custom

**Status:** implemented and locally validated; not committed, pushed or deployed. No live invitation, OTP, tester record, Play/TestFlight membership, or mobile build was changed.

## UI and validation

The new-tester form retains **1, 3, 7 (default), 14, 30 days**, and adds **Custom** for Android and iOS. Custom reveals **Number of days**, a required numeric field with min=1, max=90, step=1. Switching back to a preset hides/disables the custom field so an old invalid entry cannot block preset submission.

Invalid input is never clamped. Blank, nonnumeric, zero, negative, fractional and above-90 values show: **“Enter a whole number of days from 1 to 90.”** The shared controller validates before sending any request. Native invalid-input events also populate the inline accessible alert. Actual cards continue displaying the stored expiry timestamp, without a permanent Custom label.

The backend independently requires an integer numeric `durationDays` in **1–90**; strings, blank strings, null, booleans, fractions and out-of-range numbers are rejected safely. The preset list is informational, not an alternate authority. Both server configs advertise preset options and the custom min/max.

The iOS Extend dialog previously accepted an absolute custom timestamp. It now uses the same whole-day Custom control. The compatibility timestamp path in the shared server service remains available but is bounded to 90 days from its established calculation base; a conflicting timestamp cannot conceal an invalid `durationDays`. Oversized timestamps such as year 2099 are rejected. No stored existing expiry is clamped or modified.

## Expiry and extension contract

Android remains production-owned; iOS remains staging-owned. Both already persist PostgreSQL UTC `starts_at` / `expires_at`, so no migration is needed.

For a NEW tester, `expires_at = captured server start + durationDays × 86,400,000ms`. Custom 2 means 48 hours, 5 means 120 hours, 10 means 240 hours. Days are elapsed 24-hour periods, not midnight/calendar/DST boundaries. Access starts at Prepare/Invite, not first login or email delivery.

For an EXISTING tester, Prepare/Invite with another preset or Custom value preserves the stored expiry, identity and restrictions. Expired/revoked/disabled access is not restored by preparation.

**Explicit Extend semantics are unchanged:** add N days to `max(current expiry, server now)`. Thus active access gets N additional days after its existing expiry; already-expired access gets N days from now. This is not a reset to N days from now for active testers. The 90-day limit applies per explicit extension, not to the tester's accumulated lifetime. Revoked/Disabled access remains blocked even if the expiry is extended.

Both Extend controls accept presets and Custom. Android retains explicit confirmation, production bridge auth/rate limits and expected-expiry comparison under the row lock. iOS now also supplies the existing expected-expiry guard. A repeated/stale submission cannot add days twice. Extension is audited separately and does not change distribution eligibility or email state.

Instruction resend, OTP request/resend/verification, returning login/status checks, Play eligibility confirmation and TestFlight status handling never write the entitlement expiry. OTP TTL remains ten minutes. Expired access cannot be reactivated merely by asking for another OTP.

Admin displays continue distinguishing Active, Expired, Revoked and Disabled. Mobile denial behavior is unchanged; the richer state distinction is admin presentation. No mobile build or auth authority migration is required.

## Validation

All backend/browser tests use ephemeral local PostgreSQL schemas and mocked delivery/provider adapters. No live email or OTP was sent and no external membership was changed. Test files run serially to avoid shared-database advisory-lock collisions between fixtures; the explicit concurrency tests still pass.

- Focused production tester/bridge tests: **45/45 passed**.
- Focused dashboard/staging/iOS/reviewer/UI tests: **106/106 passed**.
- Full production backend suite: **249/249 passed**, zero failures/skips.
- Full dashboard/staging suite: **376/376 passed**, zero failures/skips.
- Android gate/controller/API integration JVM tests rerun: **42/42 passed**, zero failures/skips. No Android source change in this Custom follow-up.
- All presets plus Custom **2/5/10/90**: exact server expiry for new Android and iOS testers; default 7 retained.
- Invalid input independently rejected in services and rendered UI: blank, nonnumeric, 0, negative, fractional, 91+, coercible strings/null/booleans; no provisioning, extension, or delivery on rejection.
- Existing Prepare/Invite expiry retained despite Custom selection; explicit Custom extension, stale guard, expired renewal, revoke/disable, resend/OTP/status/eligibility preservation passed.
- Legacy absolute timestamp and mixed timestamp/duration bypass tests passed. The existing local reviewer test fixture now provisions within the 90-day bound; reviewer authority, challenge behavior and existing live records are unchanged.
- Local browser: blank/0/91/negative/decimal errors visible; Custom 2 Android Prepare; re-Prepare with Custom 90 preserves expiry; invalid 91 Extend stays open; explicit +5 days works; iOS Custom 5 Invite, re-Invite with Custom 2 preserves expiry, invalid blank Extend blocked, explicit +10 days works; full refresh clean and persisted. All mock deliveries stayed local. Responsive form layout and visible labels inspected.
- Syntax: **10 production** and **14 dashboard** changed/new JavaScript files passed; `git diff --check` passed for both worktrees and Android workspace.
- Mobile identity: **416/416** accepted production source/build hashes match. Signed version-11 release AAB and APK hashes remain unchanged. AAB SHA-256 remains `dfb0ed2d69539a8252158c05dc8674849d82738f49cc96b5e3be36bb5a6f1bfd` (`com.heyzippi.app`, 1.0.7/11).

The existing Android expiry gate remains governed by server status and a maximum 60-second lease capped by stored expiry; foreground rechecks status. The prior one-day native test passes unchanged. This validation does not claim a new live 24-hour Samsung expiry observation. No release build/upload/install was performed; only test compilation/execution ran.

## Files and deployment

The combined preset + Custom patch remains isolated in two existing worktrees:

- Production `/tmp/zippi-android-tester-production`, base `e9049a80b870b79e96b2e64eeb873db50f4d621f`.
- Dashboard/staging `/tmp/zippi-android-tester-dashboard`, base `f9ea8f57d9fe7e969421f49836e07d68d336f994`.

Custom follow-up production files changed: `lib/partnerAccessDuration.js`, `lib/partnerAccess.js`, `lib/androidTesterService.js`, `admin/public/tester-access-duration.js`, `admin/public/android-testers.js`, `admin/public/partner-access.html`, `admin/public/tester-invitations.css`. Tests: `test/androidTesterDuration.test.js`, `test/androidTesterHttp.test.js`. The previously validated duration routes/admin asset routing and prior tests remain included in the cumulative patch.

Custom follow-up dashboard files changed: shared duration/access/UI files above (excluding production-only `androidTesterService.js`), plus `lib/testerInvitations.js`, `admin/public/tester-invitations.js`, `admin/public/partner-access.js`. Tests: `test/testerInvitations.test.js`, `test/androidTesterRefresh.test.js`, `test/partnerAccessReviewer.test.js`. Existing strict remote and invitation-route forwarding remains in the cumulative patch. Documentation is `docs/tester-access-duration.md` in each worktree plus the Android report/status and curated patch/hash evidence.

**Ready for deployment review. Not deployed.** Deploy the production backend first, then dashboard/staging service after baseline reconfirmation. No migrations or new configuration values are required; keep the current default seven-day config and existing production/staging authority flags. Do not copy staging migrations or reviewer authority into production. No mobile release, Google Play/TestFlight change, mail-template change or OTP change is required.

The patches and per-file hashes in `tester-access-duration-evidence/` record the entire reviewed preset + Custom implementation against each clean base. Both patches apply cleanly. After separately authorized deployment, the admin can prepare a new controlled tester with any whole-number duration from 1 to 90 days; existing access changes only through the explicit Extend action.
