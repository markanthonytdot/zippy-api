# Demo feedback

This feature reuses the existing Express API, PostgreSQL pool, numbered migrations and signed-cookie admin authentication. No additional service or dependency is required.

## Routes

- Public `POST /v1/demo-feedback`: anonymous submission only. Strict browser origin allowlist; JSON; server validation; honeypot; keyed 15-minute rate buckets; idempotent random request IDs.
- Private `GET /admin/demo-feedback`: dashboard, after the existing admin cookie middleware.
- Private `GET /admin/api/demo-feedback`: summaries and a 50-row results page.
- Private `GET /admin/api/demo-feedback/export.csv`: all responses matching applied filters, streamed from a PostgreSQL cursor.

All feedback responses use no-store. Admin HTML and assets remain behind existing auth. Admin APIs also require the trusted `req.zippiAdmin` context. Do not mount the report/export router ahead of the existing auth middleware.

## Configuration

`ZIPPI_DEMO_FEEDBACK_ENABLED=true` enables both public submission and admin routes. Default is off. `DATABASE_URL` and `JWT_SECRET` must already be configured; the latter supplies keyed transient abuse buckets. Admin uses the existing `ZIPPI_ADMIN_SECRET`, `ZIPPI_ADMIN_SESSION_SECRET` and `ZIPPI_ADMIN_ACTOR` settings.

`DEMO_FEEDBACK_CORS_ORIGINS` optionally overrides the existing strict-CORS helper's defaults, `https://heyzippi.com` and `https://www.heyzippi.com`. The public client omits credentials. Do not enable credentialed public CORS or use a wildcard for admin data.

Run the existing `npm run migrate` workflow after confirming migrations 001–015 are already applied/approved. Feedback migrations 016 and 017 must both be applied. Migration 016 adds `demo_feedback_responses` and a separate `demo_feedback_rate_limits` table. Both revoke PUBLIC privileges and use the existing server database role. Migration 017 adds a constrained, nullable `comprehension_choice` column and permits an empty `understanding` value. It preserves every earlier row and timestamp, with no inferred choice. No booking, partner, provider or auth tables change. No hosted migration or deployment occurred during implementation.

Production history ends with `015_android_tester_eligibility.sql`; preserve it byte for byte. The feedback files are `016_demo_feedback.sql` and `017_demo_feedback_comprehension.sql`, in that order. The migration runner discovers numbered files automatically; no runner or production ledger change is needed. Existing local preview databases with the earlier feedback numbering remain untouched; use a new isolated database for the corrected full migration sequence. Never copy preview rows or an old preview ledger into production.

## Submission

JSON fields: `request_id` (random UUID v4 for idempotent retries), `comprehension_choice` (required, exactly one allowed ID), `own_words` (optional, max 2000 chars), `likelihood` (Definitely/Probably/Probably not/Definitely not), `recent_flight_shopper` (boolean), `additional_comments` (optional, max 2000 chars), `source` (optional short lowercase slug, defaults to direct), and empty `website` honeypot. Unknown fields are not stored. The response is `{ "ok": true }`; no stored data or aggregate information is exposed publicly.

Allowed choice IDs: `natural_language_flight_search`, `deals_and_price_alerts`, `automatic_trip_booking`, `general_travel_chatbot`, `not_sure`. Only the first represents the correct product description. UI labels for alternatives remain neutral.

For a minimal additive migration, API `own_words` maps to existing database column `understanding`; `additional_comments` maps to `reason`. Earlier rows have a NULL comprehension choice. They remain readable and exportable, but are excluded from comprehension denominators. Their original reason text is explicitly labeled as answering the earlier “Why did you choose that answer?” question in the dashboard. New requests cannot omit the comprehension choice. No response is automatically classified from free text.

The admin summary reports a count and percentage for every choice and “Understood Zippi correctly”. Percentages use only non-NULL choice answers within the current filters. Earlier-only or empty results show a dash, not a false 0%.

Responses have their own server-generated ID and server timestamps. Reads and exports require admin auth. No public update/delete route exists. Date filters `from` and `to` use inclusive UTC calendar days. Other filters are `source`, `likelihood`, `recent=yes|no`, `sort=newest|oldest` and `page`. Export ignores pagination while retaining the filters/sort. CSV includes the structured choice ID and its description, optional own words, likelihood, recent-shopper boolean, additional comments, source, timestamps and `Question format`. `multiple_choice_v2` identifies the revised form; `free_text_v1` identifies earlier responses whose comments answered the prior reason question. Earlier choice IDs stay blank. CSV cells are quoted and formula-like values prefixed with an apostrophe.

## Local preview

Use only an isolated loopback PostgreSQL instance. Apply migrations with the normal runner or apply 016 and 017 in order to an empty throwaway feedback-only database. Never point the preview harness or integration tests at a hosted database.

```
DEMO_FEEDBACK_DEV_DATABASE_URL=postgres://marks@127.0.0.1:55438/postgres \
DEMO_FEEDBACK_DEV_ADMIN_SECRET='<choose-a-local-only-key>' \
DEMO_FEEDBACK_WEBSITE_ROOT=/Volumes/PERSONAL/heyzippi-website \
node scripts/run_demo_feedback_dev.js
```

Public: `http://localhost:4318/demo-feedback/?source=reddit`.
Admin: `http://localhost:4318/admin/demo-feedback`.

The local harness binds loopback, rejects hosted database URLs and production mode, and uses real PostgreSQL plus the actual admin authentication. It serves the existing website and calls no suppliers, app stores, payments, AI or email services. Its randomly generated session key expires preview sessions on restart. There is no authentication bypass. No fixture data is inserted by the migration or harness.

## Validation

```
PARTNER_TEST_DATABASE_URL=postgres://marks@127.0.0.1:55438/zippi_feedback_reconciled_tests \
DEMO_FEEDBACK_TEST_DATABASE_URL=postgres://marks@127.0.0.1:55438/zippi_feedback_reconciled_tests \
npm test -- --test-concurrency=1
```

Create the named empty local test database first. Production-baseline Android fixtures also require `PARTNER_TEST_DATABASE_URL`; run test files sequentially as documented in `docs/tester-access-duration.md` on that baseline, because those fixtures share advisory-lock keys. Their explicit concurrency tests still run. Feedback integration tests create/drop their own isolated schema and use real PostgreSQL/HTTP/admin login. `test/demoFeedbackMigrations.test.js` additionally creates and removes fresh local databases for clean setup, production-schema upgrade, failed-transaction recovery, immutable ledger and rerun checks; the local test role needs CREATEDB/CREATEROLE. The fixed production-history fixture records the exact 001–015 checksums from commit `d269052d607f74a737b533184dac72bc4ecc089d`. Without the explicit feedback test database URL, both feedback PostgreSQL integration groups are skipped. Website checks include `node scripts/validate-demo-feedback.js` plus its existing generation/site/Flights/Hotels checks.

## Release and data handling

Coordinate the existing API release/migration/feature flag with the static website release. Include `/assets/zippi_demo.mp4` in the website upload; historical staging scripts omitted `.mp4`. Do not publish backend/admin source as website assets. Test anonymous read denial and authenticated exports on the deployed host. Rollback can disable the feature flag without deleting responses.

Raw IP addresses are not stored by this feature. They are used transiently in HMAC rate buckets scoped to a 15-minute window, with no link to a response. Expired buckets are cleaned on subsequent submission attempts. Existing infrastructure logs are unchanged. Free-text responses may contain voluntarily supplied personal information; the form asks participants not to include it. Decide retention/deletion before real research collection. Anonymous/source-tagged responses do not establish verified identities, unique people or representative results.

The revised poll review, file manifest, test results and screenshots are documented in `/Volumes/PERSONAL/heyzippi-website/docs/demo-feedback-comprehension-review-2026-09-13.md`. The earlier implementation report is retained separately as historical context.

The reconciled production-based candidate is isolated at `/tmp/zippi-demo-feedback-production-reconciled` on local branch `codex/demo-feedback-production-reconciled`, based on production commit `d269052d607f74a737b533184dac72bc4ecc089d`. Do not deploy the unrelated working-tree changes from the staging checkout. See `/Volumes/PERSONAL/heyzippi-website/docs/demo-feedback-migration-reconciliation-2026-09-13.md` for current release order, preflight limitations and validation.
