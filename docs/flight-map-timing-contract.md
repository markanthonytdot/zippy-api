# Production-based flight timing candidate — preparation only

Base: `0c56c33c002bc94683f75679806aefcefa0e0a65`, confirmed by the shared
production `/version` endpoint on 2026-10-16 at 12:11 UTC. Remote `main`
was `9cf96fba2cad8bfa930693b5c830ce8eebaeafe1`, an ancestor 12 commits behind
the deployed source. This candidate deliberately starts from deployed source.
No push or deployment is authorized by this document.

## Narrow contract change

Contract version stays 1. Normalized segments gain nullable `durationMinutes`,
`departingAtUtc`, `arrivingAtUtc`, and `origin.timeZone`/`destination.timeZone`.
Supplier segment duration takes precedence. Missing duration can use verified UTC
endpoints; unavailable/ambiguous evidence stays null. Full supplied dates/zones,
strict DST handling and offsets establish instants; bare local clocks never do.

Runtime changes are limited to `lib/flightSearchContract.js` and the new
`lib/flightTimingEvidence.js`. These match the reviewed timing implementation in
Partner staging `23c30e5`; none of that branch's unrelated history is imported.
Only `@js-temporal/polyfill` 0.5.1 and locked `jsbi` 4.3.2 are added. Every
pre-existing locked package object is unchanged. Nodemailer is not added.

All production migrations (including its own 015 and 016–020), server routes,
authentication, authorization, pricing, baggage, provider queries and ordering
remain unchanged. Never deploy the whole Partner staging branch to production.

## Verification

- Full candidate suite: 349 passed, zero failed/skipped, using installed matching
  dependencies and a dedicated PostgreSQL 17.11 fixture on 127.0.0.1:55434.
  Test files were serialized; deliberate concurrency tests within suites remain.
  Initial parallel execution had 8 failed counts caused by existing Android
  fixture suites sharing database-wide advisory locks for the same test email.
  No application or test was changed to resolve this harness contention.
- Local HTTP replay: actual candidate normalizer -> API response -> actual Web
  gateway -> JSON snapshot -> presentation/map. Nine scenarios include 200 captured
  schedules, direct, connection, overnight/multiple connections, repeated DST hour,
  explicit DST offsets, spring gap and missing evidence. Exact example: YYZ–DCA
  120 minutes, layover 46 minutes, DCA–MIA 168 minutes, local 5:13pm–10:47pm.
- Every scenario compares all old contract fields against the production baseline
  module after removing only additions; raw offers, prices, baggage and rankings
  remain identical. Rich price/baggage and FX fixtures are synthetic, clearly
  separate from the 200 historical captured schedules.
- Focused Web regression suite: 144 passed, zero failed/skipped. Existing Web
  candidate remains `554d06aacb34c918f04ad686d7d3b5b9518475d3` and unchanged.
- Existing iOS and Android decoders were inspected read-only: both read raw
  `data.offers` and join unchanged customer pricing from `zippiFlightSearch`.
  Added optional timing properties do not alter those selected fields. This is
  source-level compatibility evidence, not a mobile build/device acceptance.

The replay uses test-only transport substitution to a loopback HTTP server while
preserving the gateway HTTPS guard. It exercises the real normalizer, not the full
`server.js` process or native Cloudflare runtime. No supplier, AI, authentication,
email or booking calls occur. This is not live supplier or browser acceptance.
Tests ran on Node 25.6.1; deployed runtime parity remains a release check.

Evidence is outside the release tree in task-4/staging-release-evidence:
`production-timing-full-tests.log`, `production-timing-full-serial-tests.log`,
`production-http-replay.mjs`, `production-http-replay.json`, and
`production-timing-web-focused.log`.

## Remaining release gates

Production deployment needs separate explicit approval for the final exact SHA,
verified service/deployment recovery identity and runtime. Recheck source drift
and preserve production migrations/checksums before publishing. The current
production version's deployment ID is not captured by this local preparation.

Existing dependency risks are not fixed by this patch. Candidate audit reports
four affected packages (one critical, two high, one moderate), all preserved
production package versions; the two added dependencies have no reported finding.
Fresh baseline audit was blocked by automatic approval review over external
dependency metadata disclosure. Use the retained prior advisory evidence and exact
lockfile comparison; do not claim a fresh baseline audit succeeded. The critical
proxy-addr advisory's malformed trust-subnet condition is absent, but the existing
`trust proxy: true` ingress assumption remains a separate security review item.

After any approved shared API release, verify version/health, bounded normal Web
flight search and legacy contract behavior before staging Web acceptance. Ordinary
Web keeps its existing shared API route; no new identity, mobile setup, platform
grant or private QA session is required. Native desktop/mobile viewport visual QA
and live supplier acceptance remain outstanding; Chrome automation stays paused.

Recovery: restore the exact prior production deployment of this base; no database
rollback is introduced. Existing Web rollback remains Worker version
`3ca2d5a0-003b-429b-8234-21c3fed51e5d`. Use fresh QA trip state rather than clearing
user data. Partner staging's separate recovery is not a production recovery target.
