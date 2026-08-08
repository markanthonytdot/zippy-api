# Flight test booking configuration

The real flight checkout remains disabled unless all test-only configuration is supplied.

## Backend

Apply `migrations/001_flight_booking_sessions.sql`,
`migrations/002_flight_booking_quote_lines.sql`, and
`migrations/003_flight_booking_recovery_state.sql` to the Postgres database, or
call the existing `POST /admin/init` endpoint after deploying this version.

Set these environment variables on `zippy-api`:

- `FLIGHT_TEST_BOOKING_ENABLED=1`
- `STRIPE_SECRET_KEY=sk_test_...`
- `DUFFEL_FLIGHTS_BOOKING_TOKEN=duffel_test_...` with offer search and order creation permission
- `DUFFEL_FLIGHTS_KEY=duffel_test_...` should use the same Duffel test account/token for normal search when the booking switch is not enabled
- `DATABASE_URL=postgresql://...`
- `JWT_SECRET=...` and the existing auth settings must be present because checkout requires verified authentication

Optional settings:

- `FLIGHT_ZIPPI_FEE_MINOR=499` keeps the configured checkout fee in minor currency units
- `FLIGHT_DUFFEL_ORDER_TIMEOUT_MS=130000` should not be reduced below Duffel's booking guidance
- `FLIGHT_SEARCH_CORS_ORIGINS=https://www.heyzippi.com,https://heyzippi.com`
  overrides the strict browser origin allowlist when a controlled preview origin
  is required

The server refuses booking if the Stripe key is not a test secret key or the Duffel booking token is not a test token.

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
