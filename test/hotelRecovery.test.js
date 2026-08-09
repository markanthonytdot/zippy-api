const test = require("node:test");
const assert = require("node:assert/strict");
const { createHotelDuffelBookingLookup } = require("../lib/hotelDuffelBookingLookup");
const { retryDelayMs, validateReconciledBooking, validateRefund } = require("../lib/hotelRecovery");

const session = {
  id: "11111111-1111-4111-8111-111111111111",
  stripe_payment_intent_id: "pi_test",
  duffel_quote_id: "quo_test",
  duffel_rate_id: "rat_test",
  provider_currency: "USD",
  provider_total_minor: 10000,
  customer_currency: "CAD",
  customer_total_minor: 13500,
};

test("Hotel unknown-outcome reconciliation accepts only one exact metadata match", async () => {
  const booking = { id: "bok_test", status: "confirmed", metadata: {
    zippi_booking_session_id: session.id,
    stripe_payment_intent_id: session.stripe_payment_intent_id,
    zippi_duffel_quote_id: session.duffel_quote_id,
    zippi_duffel_rate_id: session.duffel_rate_id,
    zippi_provider_currency: "USD",
    zippi_provider_total_minor: "10000",
    zippi_customer_currency: "CAD",
    zippi_customer_total_minor: "13500",
  } };
  const lookup = createHotelDuffelBookingLookup({
    token: "duffel_test_token",
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ data: [booking] }) }),
  });
  const result = await lookup.findBookingForSession(session);
  assert.equal(result.status, "found");
  assert.equal(validateReconciledBooking(result.booking, session), true);
  assert.equal(validateReconciledBooking({ ...booking, metadata: { ...booking.metadata, zippi_duffel_quote_id: "quo_other" } }, session), false);
});

test("Hotel recovery never treats missing or duplicate Duffel matches as confirmed", async () => {
  for (const data of [[], [
    { id: "bok_1", metadata: { zippi_booking_session_id: session.id } },
    { id: "bok_2", metadata: { zippi_booking_session_id: session.id } },
  ]]) {
    const lookup = createHotelDuffelBookingLookup({
      token: "duffel_test_token",
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ data }) }),
    });
    const result = await lookup.findBookingForSession(session);
    assert.notEqual(result.status, "found");
  }
});

test("Hotel refund reconciliation requires the full authoritative Stripe refund", () => {
  assert.equal(validateRefund({ id: "re_test", status: "succeeded", payment_intent: "pi_test", currency: "cad", amount: 13500,
    metadata: { booking_session_id: session.id } }, session), true);
  assert.equal(validateRefund({ id: "re_test", status: "succeeded", payment_intent: "pi_test", currency: "cad", amount: 1,
    metadata: { booking_session_id: session.id } }, session), false);
  assert.equal(retryDelayMs(20), 6 * 60 * 60 * 1000);
});
