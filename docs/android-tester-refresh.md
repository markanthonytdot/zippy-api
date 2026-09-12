# Android tester persistent load message — 2026-09-12

## Live findings

A new browser page at `https://zippi-partner-staging.onrender.com/admin/partner-access` loaded with both message areas empty. Selecting Android and using Refresh list remained clean. The designated tester remained Active / Confirmed / Not sent, with Send enabled. No action button that mutates tester state was used in this investigation.

Switching to iOS loaded the invitation policy/readiness, four partner rows and their completed invitation statuses. No loading placeholders or browser warning/error log entries remained. No invitation or OTP was sent.

The initial document loads these three scripts and three application reads:

| Script | Browser request | Authority / result observed |
| --- | --- | --- |
| `partner-access.js` | GET `/admin/api/partner-access` | Staging iOS partner list; rendered normally |
| `tester-invitations.js` | GET `/admin/api/tester-invitations` | Staging iOS config, organizations and invitation statuses in one response; rendered normally |
| `android-testers.js` | GET `/admin/api/android-testers` | Staging authenticated proxy to production GET `/internal/android-tester-admin`; Android config and confirmed tester rendered normally |

There is no separate initial invitation-config/status request: those values are aggregated in the iOS invitation-list response. All browser application requests are same-origin; only the private server bridge contacts production.

No failing fresh-load request was reproduced. The browser's available error logs were empty. Raw network statuses/bodies for the user's failing session were not recovered; do not describe an assumed HTTP 200, 4xx/5xx, CORS failure or iOS failure as a captured trace. The previous confirmation action uses POST `/admin/api/android-testers` on staging, forwarded to production. Its historical transport failure remains unproven.

## Proven frontend defect

The Android action catch writes the raw fetch/response exception message (including `Load failed`) into the shared invitation message area. The automatic and explicit list refreshes update configuration, cards, eligibility and Send enablement but do not clear that previous message. Thus a successful GET can display Confirmed and an enabled Send next to an obsolete action error. This is reproducible with the shipped controller and a controlled rejected action followed by a successful read.

This proves stale-error retention after **Refresh list**. It does not prove the reported behavior after a genuine fresh document load; fresh navigation in the inspected session was clean. No initial-load catch in these invitation scripts writes the literal `Load failed` into that message area. That distinction must remain explicit.

## Scoped correction

Candidate worktree: `/tmp/zippi-android-tester-dashboard`, based on deployed dashboard `762d314661a8e50dc12974ecdfd4aafb933d3b89`.

- `admin/public/android-testers.js`: track messages belonging to Android failures; successful explicit Refresh list clears only the same recovered Android error. Failed reads retain a warning. Refresh during an active action is ignored. Unrelated/iOS messages and newer action messages are not cleared. Automatic reconciliation still retains the action outcome so an uncertain mutation is not reported as successful.
- `test/androidTesterRefresh.test.js`: executes the actual controller against a small DOM/HTTP boundary; tests rejected confirmation plus successful persisted-state refresh, failed-then-recovered reads, unrelated/iOS messages, and in-flight action protection. Synthetic local data only; no live writes or delivery.

Before the fix, three of the four new tests failed, including the exact stale `Load failed` assertion. After the fix all four passed. Existing authenticated Android proxy / separate iOS dispatch, guards and invitation tests also passed.

Validation: 16 focused passed, one database-dependent test skipped; full `node --test test/*.test.js`: **292 passed, 0 failed, 3 database-dependent suites skipped** (295 total). Syntax and `git diff --check` passed. The first broader run stalled because child servers lacked candidate-local dependencies; it was stopped, rerun successfully using an ignored link to existing dependencies, then that link was removed. No dependency files changed.

## Deployment and readiness

The user explicitly authorized one scoped dashboard commit and deployment of that exact newly created commit to the existing tester dashboard. This changeset contains only the frontend correction, focused tests, and this report. No backend/mobile/configuration/migration change is required. No tester mutation, email, OTP or Play change is authorized.

The live tester remains ready according to persisted entitlement/eligibility, and the newly opened dashboard is visually clean. Do not claim the user's original tab or reported full-document reload failure has been fully diagnosed. After deployment, verify the running revision, clean full-page load and explicit refresh, preserved Active / Confirmed / Not sent state, enabled Send, and unchanged iOS read-only dashboard behavior. Stop before Send. Live deployment results are recorded separately after verification.
