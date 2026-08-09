const test = require("node:test");
const assert = require("node:assert/strict");
const { resolveFlightBookingMode } = require("../lib/flightBookingMode");

test("flight booking mode defaults disabled and fail closed", () => {
  const config = resolveFlightBookingMode({});
  assert.equal(config.mode, "disabled");
  assert.equal(config.checkoutEnabled, false);
});

test("test mode accepts only matching test credentials", () => {
  const config = resolveFlightBookingMode({
    FLIGHT_BOOKING_MODE: "test",
    FLIGHT_TEST_BOOKING_ENABLED: "1",
    FLIGHT_STRIPE_TEST_SECRET_KEY: "sk_test_example",
    FLIGHT_STRIPE_TEST_WEBHOOK_SECRET: "whsec_test",
    DUFFEL_FLIGHTS_TEST_BOOKING_TOKEN: "duffel_test_example",
  });
  assert.equal(config.checkoutEnabled, true);
  assert.deepEqual(config.issues, []);
});

test("live mode accepts only matching live credentials and explicit internal enablement", () => {
  const config = resolveFlightBookingMode({
    FLIGHT_BOOKING_MODE: "live",
    FLIGHT_INTERNAL_LIVE_BOOKING_ENABLED: "1",
    FLIGHT_STRIPE_LIVE_SECRET_KEY: "sk_live_example",
    FLIGHT_STRIPE_LIVE_WEBHOOK_SECRET: "whsec_live",
    DUFFEL_FLIGHTS_LIVE_BOOKING_TOKEN: "duffel_live_example",
  });
  assert.equal(config.checkoutEnabled, true);
  assert.deepEqual(config.issues, []);
});

test("mixed live and test credentials fail closed", () => {
  const config = resolveFlightBookingMode({
    FLIGHT_BOOKING_MODE: "live",
    FLIGHT_INTERNAL_LIVE_BOOKING_ENABLED: "1",
    FLIGHT_STRIPE_LIVE_SECRET_KEY: "sk_test_wrong",
    FLIGHT_STRIPE_LIVE_WEBHOOK_SECRET: "whsec_live",
    DUFFEL_FLIGHTS_LIVE_BOOKING_TOKEN: "duffel_live_example",
  });
  assert.equal(config.checkoutEnabled, false);
  assert.ok(config.issues.includes("stripe_credential_mode_mismatch"));
});

test("public checkout flag always fails closed", () => {
  const config = resolveFlightBookingMode({
    FLIGHT_BOOKING_MODE: "test",
    FLIGHT_TEST_BOOKING_ENABLED: "1",
    FLIGHT_PUBLIC_CHECKOUT_ENABLED: "1",
    FLIGHT_STRIPE_TEST_SECRET_KEY: "sk_test_example",
    FLIGHT_STRIPE_TEST_WEBHOOK_SECRET: "whsec_test",
    DUFFEL_FLIGHTS_TEST_BOOKING_TOKEN: "duffel_test_example",
  });
  assert.equal(config.checkoutEnabled, false);
  assert.ok(config.issues.includes("public_checkout_must_remain_disabled"));
});
