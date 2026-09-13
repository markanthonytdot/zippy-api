# Package demo feedback — local review, 2026-09-13

Status: implemented and validated locally. No production migrations, deploys, environment changes, store-console changes, or production research submissions were performed for this feature.

## Architecture and isolation

This worktree starts at the confirmed live flight-feedback API revision `3e199ed9d4ea2e6c4921975b5331fcf04ef768b7`. Package responses and CTA events live in separate tables; existing flight submission validation, reporting, CSV and rate-limit service code are unchanged. Both research areas use the existing admin authentication. The public package router reuses the existing JSON/CORS/request-limit/no-public-read middleware.

Enable only after migration 018 with `ZIPPI_PACKAGE_FEEDBACK_ENABLED=true`. It is off by default. Optional `PACKAGE_FEEDBACK_CORS_ORIGINS` uses the same canonical heyzippi.com/www defaults as flight feedback when omitted. No new secret or dependency is required. Existing server JWT secret keys the separate rate buckets; existing admin secrets/cookies protect the dashboard.

Routes:

- `POST /v1/package-feedback`: submit-only package answers.
- `POST /v1/package-feedback/events`: anonymous optional-CTA click event.
- `/admin/package-feedback`: authenticated package dashboard.
- `/admin/api/package-feedback`: authenticated report.
- `/admin/api/package-feedback/export.csv`: authenticated filtered export.
- `/admin/assets/package-feedback.{js,css}`: authenticated assets.

The website's `/package-feedback/` is hidden from public navigation, homepage, footer and sitemap, and carries noindex/nofollow/noarchive. It reuses the supplied 57.621-second `assets/package_demo.mp4` unchanged.

## Data and event semantics

`018_package_demo_feedback.sql` adds only:

- `package_feedback_responses`: independent UUID, idempotency request UUID, constrained `demo_type=package`, likelihood, usefulness, optional comment (2,000 characters maximum), source slug, entry path, submitted/created/updated timestamps.
- `package_feedback_clicks`: event UUID, fixed click event type, source slug and timestamp. No visitor/response foreign keys.
- `package_feedback_rate_limits`: expiring HMAC bucket, bounded attempt count and expiry. Separate click and response namespaces; 10 attempts per 15-minute window each. No raw IP storage in these tables.

No flight columns, historical rows, existing migration bytes, database roles, existing policies, or original flight metric denominators are changed. PUBLIC receives no privileges on the new tables. The rollout does not require resetting flight answers or copying real identities into test data.

After successful flight submission only, the page reveals a secondary native link: “Want to see another Zippi demo?” / “See how Zippi could help find a flight + hotel package within your total trip budget.” / “Watch the package demo”. No automatic navigation. The link carries the normalized acquisition source and `entry_path=flight_thank_you`. Independent package links default to `entry_path=direct` and `source=direct` if no valid source slug is provided.

One fresh, in-memory event UUID is created after flight success. It differs from the flight request ID, never appears in the URL or package answer, and deduplicates repeated clicks/retries from that completed form. `fetch(..., keepalive:true)` is best effort and never cancels/delays native navigation. No cookie, local storage, persistent cross-site ID, participant profile, or response-to-response join is added.

The anonymous funnel uses source/date filters only: X = flight submissions; Y = distinct recorded CTA event IDs; Z = package submissions bearing `flight_thank_you`. Rates are Y/X and Z/Y, with an em dash for a zero denominator. Answer and entry filters do not change this funnel. These are event counts, not unique people, verified click-to-answer cohorts, or causal conversion attribution. Links can be shared, clients can retry/reload, delivery can fail, and steps may span dates; period rates can exceed 100%. Select a date range from package launch onward so earlier flight responses without this CTA do not dilute comparisons. No claim of bot-proof or uniquely identified users is made.

## Admin and CSV

Separate flight/package navigation; package total, all four likelihood counts/percentages, combined positive count/percentage, usefulness counts/percentages, source breakdown, direct/flight thank-you response counts, funnel and paginated answer table. Filters: source, likelihood, usefulness, entry path, UTC start/end date and sort order.

The package CSV exports every matching response across pagination with: Response ID, Demo type, Submitted at (UTC), Source, Entry path, Likelihood to use, More useful than separate search, Additional comments. The original flight CSV is unchanged. Shared CSV escaping protects quotes, commas, line breaks and spreadsheet formula prefixes. Comments and source labels render through textContent.

## Validation

- 306 API tests pass, zero failures/skips, including 21 new package assertions/test cases in the package suites.
- Real isolated PostgreSQL tests: all 18 migrations fresh, verified 001–017 upgrade preserving flight rows/constraints/columns/ledger timestamps, deterministic rerun, intentional 018 failure rollback and clean resume.
- Public POST validation, missing/invalid choices, source/entry validation, optional comments, retry conflicts, CORS, body limits, no public GET/summary/CSV, existing signed-cookie login, tampered/expired cookies, protected assets, separate rate limits, package reports, funnel filters and filtered all-page CSV.
- Exact before/after flight row and report snapshots remain equal after package writes and clicks.
- Browser local smoke: completed flight row before CTA, no click until native CTA clicked, Reddit source preservation, correct flight_thank_you answer, separate standalone family/direct answer, required radio validation, keyboard arrow selection with visible focus, dashboard filters and CSV download, HTML-looking comment safely rendered as text.
- Website generation/validators pass: 306 HTML pages, 300 canonical URLs, links/anchors, sitemap, social/schema metadata, EN/ES/PT coverage, flight and hotel contracts, both research-page validators, deterministic regeneration.
- Actual 1440px, 768px, 390px and 320px package and admin viewports have no page horizontal overflow. Flight thank-you CTA checked at 390px/320px. Radio labels are 50px tall; optional comment is 76px/two lines. Native video fits and loads metadata.
- Node syntax checks and git diff whitespace checks pass. No TypeScript compiler, lint script or bundler is configured in these projects; no dependencies/lockfiles changed.

The separate local review database is `zippi_package_feedback_review` at loopback port 55438, with synthetic data only. The original 4318 preview database and its existing responses were not reset. New preview runs at `http://localhost:4319`; use `DEMO_FEEDBACK_DEV_PORT=4319` and a local-only `DEMO_FEEDBACK_DEV_ADMIN_SECRET` with `scripts/run_demo_feedback_dev.js`. Local pages cannot submit to production.

## Production checkpoint and future release order (not executed)

Read-only inspection at 2026-09-13 17:44 UTC confirmed migrations 001–017, one existing flight smoke response, healthy live API commit above, Render deployment `dep-dajdmdvqj5pc73d7glu0`, and no deploy in progress. 018 was confirmed unused. The prior flight website/API deployment is complete; its user-authenticated live admin/CSV review remains a separate follow-up. This feature does not alter that release, its artifact, or its rollback bundle.

After explicit review approval:

1. Recheck live revision, deployments and ledger checksums/next number. Stop if unexpected drift or a concurrent release exists; do not overwrite or rewrite applied history.
2. Freeze a package API revision based on the intended live revision and construct a website bundle from the last deployed allowlisted artifact plus only reviewed package changes. Do not deploy the dirty canonical API checkout or the website source/docs indiscriminately. Include unchanged supplied `assets/package_demo.mp4`.
3. Apply only migration 018 using the normal checksum/ledger runner. Verify original flight ledger and rows, new empty tables and PUBLIC privileges. Do not seed production with local samples.
4. Deploy reviewed API with the package flag off; verify health, revision and unchanged flight/public/admin protections. Enable `ZIPPI_PACKAGE_FEEDBACK_ENABLED=true` only after those checks pass; use existing admin authentication to verify package reports/CSV and anonymous read denial.
5. Publish only the reviewed website artifact once package API is healthy. Verify real video delivery, both sources/entry paths, one authorized labeled smoke per needed flow, exact funnel deltas, desktop/mobile, noindex and unchanged flight reporting. Stop on any migration, auth, security or health failure.
6. Rollback application/website artifacts and disable the package flag if required. Keep additive 018 tables and any responses; do not delete answers or remove an applied ledger entry as an application rollback.
