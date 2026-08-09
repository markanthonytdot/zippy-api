const test = require("node:test");
const assert = require("node:assert/strict");
const { requiredDuffelStaysToken } = require("../scripts/run_hotel_recovery_worker");

test("Hotel recovery uses the same explicit Stays token fallback as the web service", () => {
  assert.equal(requiredDuffelStaysToken({ DUFFEL_STAYS_KEY: "duffel_test_stays" }), "duffel_test_stays");
  assert.equal(requiredDuffelStaysToken({ DUFFEL_API_KEY: "duffel_test_shared" }), "duffel_test_shared");
  assert.equal(
    requiredDuffelStaysToken({ DUFFEL_STAYS_KEY: "duffel_test_stays", DUFFEL_API_KEY: "duffel_test_shared" }),
    "duffel_test_stays"
  );
});

test("Hotel recovery fails closed when neither Duffel Stays token source is configured", () => {
  assert.throws(() => requiredDuffelStaysToken({}), /DUFFEL_STAYS_KEY or DUFFEL_API_KEY is required/);
});
