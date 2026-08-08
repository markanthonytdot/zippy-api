# Flight test booking configuration

The real flight checkout remains disabled unless all test-only configuration is supplied.

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

Set these environment variables on `zippy-api`:

- `FLIGHT_TEST_BOOKING_ENABLED=1`
- `STRIPE_SECRET_KEY=sk_test_...`
- `STRIPE_WEBHOOK_SECRET=whsec_...` from the Stripe test-mode webhook endpoint
- `DUFFEL_FLIGHTS_BOOKING_TOKEN=duffel_test_...` with offer search and order creation permission
- `DUFFEL_FLIGHTS_KEY=duffel_test_...` should use the same Duffel test account/token for normal search when the booking switch is not enabled
- `DATABASE_URL=postgresql://...`
- `JWT_SECRET=...` and the existing auth settings must be present because checkout requires verified authentication

Configure the Stripe test-mode endpoint as `POST /v1/webhooks/stripe`. The
route verifies the Stripe signature against the unparsed request body, records
each event ID once, and applies only monotonic state transitions whose payment
intent, amount, and currency match the durable booking session. Do not reuse a
live-mode signing secret.

Optional settings:

- `FLIGHT_ZIPPI_FEE_MINOR=299` keeps the current TEST checkout fee in minor currency units
- `FLIGHT_DUFFEL_ORDER_TIMEOUT_MS=130000` should not be reduced below Duffel's booking guidance
- `FLIGHT_RECOVERY_DUFFEL_TIMEOUT_MS=15000` bounds the worker's read-only order lookup
- `FLIGHT_RECOVERY_INTERVAL_MS=30000` controls the worker polling interval
- `FLIGHT_SEARCH_CORS_ORIGINS=https://www.heyzippi.com,https://heyzippi.com`
  overrides the strict browser origin allowlist when a controlled preview origin
  is required

The server refuses booking if the Stripe key is not a test secret key or the Duffel booking token is not a test token.

After deployment, compare `GET /version` field `deployCommit` with the expected
Render Git commit. It is sourced only from a validated `RENDER_GIT_COMMIT` value
and is `null` when Render does not provide a valid hexadecimal commit.

## iOS debug scheme

Add these environment variables to the Run action of the internal Xcode scheme:

- `ZIPPI_ENABLE_FLIGHT_CHECKOUT=1`
- `STRIPE_PUBLISHABLE_KEY=pk_test_...`

Alternatively, add the launch argument `-ZippiFlightCheckout` and supply the test publishable key through the empty `STRIPE_PUBLISHABLE_KEY` Info.plist entry. Release builds keep checkout disabled regardless of these values.

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

Checkout claims use a short lease. A stale claim may be retried only when the
durable Duffel POST marker was never written. Once order submission starts, an
uncertain outcome is held for manual reconciliation and is never retried
automatically. Stripe refunds remain pending until Stripe reports success.

## Render recovery worker

Run a separate Render background worker from this repository with:

```sh
npm run worker:flight-recovery
```

The worker requires the same `DATABASE_URL`, `STRIPE_SECRET_KEY`,
`DUFFEL_FLIGHTS_BOOKING_TOKEN`, and `DUFFEL_API_VERSION` settings as the test
booking service. Run `npm run migrate` successfully before starting it. The
database claim lease, fencing token, and `FOR UPDATE SKIP LOCKED` claim make
multiple worker instances safe, though one instance is sufficient initially.
Restart repair scans recreate missing work for stale booking claims, unknown
Duffel outcomes, and refund-pending sessions.

Unknown airline outcomes use only `GET /air/orders` filtered by the exact offer
ID. A result is confirmed only when exactly one test-mode order matches the
session, Stripe intent, offer, currency, amount, and Zippi metadata. Absence is
never treated as proof that no order exists; zero, ambiguous, mismatched, or
live-mode results back off and ultimately remain in `manual_review`. The worker
never submits a replacement Duffel order and never refunds an unknown airline
outcome. Refund recovery uses the original deterministic Stripe idempotency key.

A future Duffel `order.created` integration should use a separately configured
signed webhook, persist event IDs, and tolerate duplicate and out-of-order
delivery. No Duffel dashboard webhook or signing secret is configured by this
change.
