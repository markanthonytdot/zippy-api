# Flight booking environment configuration

Flight booking is explicit-mode and fail-closed. `FLIGHT_BOOKING_MODE` must be
`test` or `live`; an absent, invalid, incomplete, or mixed-mode configuration
leaves checkout disabled. Public Release checkout is a separate switch and must
remain off during controlled testing.

## Backend

Configure the Render service's **Pre-Deploy Command** as exactly:

```sh
npm run migrate
```

The command requires `DATABASE_URL`, takes a Postgres advisory lock, verifies
the checksum ledger, and applies each unapplied file in `migrations/` in its own
transaction. A pre-existing migration 001 is recorded only after its baseline
schema is verified. Any checksum mismatch, partial baseline, or SQL failure must
fail the deployment; do not bypass the runner with `POST /admin/init`.

Migration 002 preserves historical accounting honestly: legacy rows did not
store a separate Duffel base-fare/tax split, so their `base_fare_minor` is
backfilled from the legacy `offer_minor` total and `taxes_minor` remains `NULL`.
New booking sessions persist the provider-authored base fare and taxes as
separate values. Do not infer zero historical tax from a `NULL` value.

Rollback rule: never edit, delete, or renumber an applied migration. Roll back
application code only when the deployed schema remains backward compatible;
otherwise ship a new forward-only corrective migration. Restore a database
backup only as a separately coordinated incident action, not as an automatic
Render rollback step.

Set these environment variables on `zippy-api` for TEST:

- `FLIGHT_BOOKING_MODE=test`
- `FLIGHT_TEST_BOOKING_ENABLED=1`
- `FLIGHT_PUBLIC_CHECKOUT_ENABLED=0`
- `FLIGHT_STRIPE_TEST_SECRET_KEY=sk_test_...`
- `FLIGHT_STRIPE_TEST_PUBLISHABLE_KEY=pk_test_...`
- `FLIGHT_STRIPE_TEST_WEBHOOK_SECRET=whsec_...`
- `DUFFEL_FLIGHTS_TEST_BOOKING_TOKEN=duffel_test_...` with offer search and order creation permission
- `DUFFEL_FLIGHTS_KEY=duffel_test_...` should use the same Duffel test account/token for normal search when the booking switch is not enabled
- `DATABASE_URL=postgresql://...`
- `JWT_SECRET=...` and the existing auth settings must be present because checkout requires verified authentication

Legacy `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and
`DUFFEL_FLIGHTS_BOOKING_TOKEN` remain TEST-only fallbacks during migration.
They are never used for LIVE mode.

For one future controlled LIVE booking, use separate variables:

- `FLIGHT_BOOKING_MODE=live`
- `FLIGHT_INTERNAL_LIVE_BOOKING_ENABLED=1`
- `FLIGHT_PUBLIC_CHECKOUT_ENABLED=0`
- `FLIGHT_STRIPE_LIVE_SECRET_KEY=sk_live_...`
- `FLIGHT_STRIPE_LIVE_PUBLISHABLE_KEY=pk_live_...`
- `FLIGHT_STRIPE_LIVE_WEBHOOK_SECRET=whsec_...` from the LIVE endpoint
- `DUFFEL_FLIGHTS_LIVE_BOOKING_TOKEN=duffel_live_...` with search, offer read, and order creation permission
- `FLIGHT_RECOVERY_WORKER_ENABLED=1` on the API and recovery worker

Do not supply TEST credentials in LIVE variables or LIVE credentials in TEST
variables. Credential prefixes, Stripe webhook `livemode`, persisted session
mode, and returned Duffel order `live_mode` are all checked.

Configure the active Stripe endpoint as `POST /v1/webhooks/stripe`. TEST and
LIVE endpoints must use separate signing secrets. Subscribe to:

- `payment_intent.succeeded`
- `payment_intent.payment_failed`
- `payment_intent.canceled`
- `charge.succeeded` for actual processing-fee reconciliation
- `refund.created`
- `refund.updated`
- `refund.failed`

The
route verifies the Stripe signature against the unparsed request body, records
each event ID once, and applies only monotonic state transitions whose payment
intent, amount, and currency match the durable booking session. It rejects an
event whose Stripe `livemode` value does not match the active booking mode.

Optional settings:

- `FLIGHT_ZIPPI_FEE_MINOR` preserves the currently deployed booking fee in minor currency units
- `FLIGHT_DUFFEL_ORDER_TIMEOUT_MS=130000` should not be reduced below Duffel's booking guidance
- `FLIGHT_RECOVERY_DUFFEL_TIMEOUT_MS=15000` bounds the worker's read-only order lookup
- `FLIGHT_RECOVERY_INTERVAL_MS=30000` controls the worker polling interval
- `FLIGHT_SEARCH_CORS_ORIGINS=https://www.heyzippi.com,https://heyzippi.com`
  overrides the strict browser origin allowlist when a controlled preview origin
  is required

The server refuses booking unless both credentials match the explicit mode and
the mode-specific webhook secret and enable switch are present. It also refuses
to run with public checkout enabled during this controlled phase.

`GET /health/flights/readiness` is non-destructive and reports database,
pricing, currency, mode-specific Stripe/Duffel configuration, webhook,
recovery-worker, and public-checkout state without returning credentials. Add
`?probe=1` to perform a read-only authenticated Duffel Orders request. Duffel
does not provide a safe API balance-read contract; before a LIVE payment an
operator must separately confirm in Duffel that the account is activated and
has enough balance to cover the complete provider order.

After deployment, compare `GET /version` field `deployCommit` with the expected
Render Git commit. It is sourced only from a validated `RENDER_GIT_COMMIT` value
and is `null` when Render does not provide a valid hexadecimal commit.

## iOS schemes

Debug reads a `pk_test_...` key from the untracked
`Config/DebugSecrets.xcconfig`. `FeatureFlags.flightCheckoutEnabled` remains
Debug-only and does not depend on an ephemeral launch environment variable.

The `Zippy Internal Live` scheme uses the distinct `InternalLive` build
configuration and the untracked `Config/InternalLiveSecrets.xcconfig`:

```xcconfig
STRIPE_PUBLISHABLE_KEY = pk_live_...
```

InternalLive rejects `pk_test_` keys, Debug rejects `pk_live_` keys, and public
Release compiles with flight checkout disabled and no Stripe publishable key.
Apple Pay remains unconfigured.

Use a one-way offer or one atomic bundled round-trip Duffel offer, a
signed-in/dev-authenticated test user, and a Stripe test card. Never send
independent outbound and return offer IDs. Do not use live Stripe or Duffel
credentials.

`POST /v1/flights/payment/setup` returns the server-authored `quote` (base fare,
taxes when supplied by Duffel, services, configured Zippi fee, Duffel total,
and charge total). A stale client total receives the same quote in the
`checkout_price_changed` error details and must return to review before payment.

`POST /v1/flights/booking/quote` accepts the checkout offer and selected-service
fields and returns the same authoritative quote without creating a booking
session or Stripe PaymentIntent. Payment setup is the first durable session.
Submitted checkout travelers use `travelerType` values `adult`, `child`, or
`infant_without_seat`; nationality and passport country use uppercase ISO
3166-1 alpha-2 codes.

`GET /v1/flights/booking/sessions/:bookingSessionId` is verified-auth and
ownership scoped. It refreshes Stripe payment state and returns the durable
booking status, quote, failure/recovery state, and persisted confirmation. It
does not automatically retry Duffel orders after submission; ambiguous outcomes
require reconciliation.

`GET /v1/flights/booking/sessions` is also verified-auth and returns only the
current user's non-final sessions in the active booking mode. iOS uses it to
discover and resume payment/booking recovery after reinstall, device change,
crash, or app termination. Confirmed trips continue to use Booked Trips and are
not duplicated by this feed.

Checkout claims use a short lease. A stale claim may be retried only when the
durable Duffel POST marker was never written. Once order submission starts, an
uncertain outcome is held for manual reconciliation and is never retried
automatically. Stripe refunds remain pending until Stripe reports success.

## Render recovery worker

Run a separate Render background worker from this repository with:

```sh
npm run worker:flight-recovery
```

The worker requires the same `DATABASE_URL`, explicit booking mode,
mode-specific Stripe/Duffel credentials, `FLIGHT_RECOVERY_WORKER_ENABLED=1`,
and `DUFFEL_API_VERSION` as the API service. Run `npm run migrate` successfully
before starting it. The
database claim lease, fencing token, and `FOR UPDATE SKIP LOCKED` claim make
multiple worker instances safe, though one instance is sufficient initially.
Restart repair scans recreate missing work for stale booking claims, unknown
Duffel outcomes, and refund-pending sessions.

Unknown airline outcomes use only `GET /air/orders` filtered by the exact offer
ID. A result is confirmed only when exactly one test-mode order matches the
session, active mode, Stripe intent, offer, currency, amount, and Zippi metadata. Absence is
never treated as proof that no order exists; zero, ambiguous, mismatched, or
live-mode results back off and ultimately remain in `manual_review`. The worker
never submits a replacement Duffel order and never refunds an unknown airline
outcome. Refund recovery uses the original deterministic Stripe idempotency key.

A future Duffel `order.created` integration should use a separately configured
signed webhook, persist event IDs, and tolerate duplicate and out-of-order
delivery. No Duffel dashboard webhook or signing secret is configured by this
change.
