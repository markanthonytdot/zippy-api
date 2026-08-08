# Flight test booking configuration

The real flight checkout remains disabled unless all test-only configuration is supplied.

## Backend

Apply `migrations/001_flight_booking_sessions.sql` to the Postgres database, or call the existing `POST /admin/init` endpoint after deploying this version.

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

The server refuses booking if the Stripe key is not a test secret key or the Duffel booking token is not a test token.

## iOS debug scheme

Add these environment variables to the Run action of the internal Xcode scheme:

- `ZIPPI_ENABLE_FLIGHT_CHECKOUT=1`
- `STRIPE_PUBLISHABLE_KEY=pk_test_...`

Alternatively, add the launch argument `-ZippiFlightCheckout` and supply the test publishable key through the empty `STRIPE_PUBLISHABLE_KEY` Info.plist entry. Release builds keep checkout disabled regardless of these values.

Use a one-way Duffel test offer, a signed-in/dev-authenticated test user, and a Stripe test card. Do not use live Stripe or Duffel credentials.
