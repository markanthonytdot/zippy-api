# Hotel reliability staging candidate

Base: staging's verified deployed commit `9feb1c8cdd07fbf9dcb7d776a79afbf8b9e0890f`.
Branch: `codex/hotel-rate-limit-staging` (separate checkout).

Only six production files change: server.js; lib/hotelDiscoveryPricing.js; lib/hotelRateLimit.js; lib/hotelReadBudget.js; lib/hotelDiscoveryCoalescer.js; lib/hotelReadReliability.js.
Existing Partner code in the base is preserved. Uncommitted Partner admin assets, partnerAccess/testerInvitation modules/tests and the QA_GROUP/iosQA hunks from the shared checkout are excluded. No changes to production service or mobile source.

Staging target: `srv-dagq12ht0dsc73a7dm40`, https://zippi-partner-staging.onrender.com.
Explicit finite staging configuration: HOTELS_RPM=10, HOTELS_HOURLY=4, HOTELS_DAILY=6; HOTEL_PROVIDER_MINUTE/HOUR/DAY=3; HOTEL_TRAFFIC_CLASS=QA. Existing auth and booking-disabled settings remain. These values apply only to this staging service. Save configuration without auto-deployment, then deploy the exact isolated commit.

Added 13 real HTTP cases in test/hotelStagingHttp.test.js. They start the actual Express server in isolated child processes with an explicit, test-only localhost provider preload. No provider credentials or external requests are used. They verify minute/hour/day resets, counter accounting, single-debit coalescing, mismatched identity/facts, cancellation, QA spoofing, provider429 and route contracts over real sockets. The preload is never imported by the production start command and cannot be enabled by a caller. Run on Render during the build command to collect hosted-runtime evidence. Separate external staging smoke uses real provider test inventory and the finite three-operation aggregate cap.

Local candidate validation: 102 focused hotel tests passed (89 existing + 13 HTTP); full suite 245 passed, 3 existing database-dependent skips (248 total). No production fixes were required by the real HTTP tests. Live staging results will be recorded separately; this candidate document is not a hosted acceptance claim.
