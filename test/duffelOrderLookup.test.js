const test = require("node:test");
const assert = require("node:assert/strict");

const { createDuffelOrderLookup } = require("../lib/duffelOrderLookup");

const session = {
  id: "11111111-1111-4111-8111-111111111111",
  stripe_payment_intent_id: "pi_exact",
  duffel_offer_id: "off_exact",
  currency: "USD",
  duffel_total_minor: "12345",
  offer_snapshot: { total_amount: "120.00" },
};

function verifiedOrder(overrides = {}) {
  return {
    id: "ord_exact",
    live_mode: false,
    offer_id: "off_exact",
    total_currency: "USD",
    total_amount: "123.45",
    metadata: {
      zippi_booking_session_id: session.id,
      stripe_payment_intent_id: "pi_exact",
      zippi_duffel_offer_id: "off_exact",
      zippi_currency: "USD",
      zippi_duffel_total_minor: "12345",
    },
    ...overrides,
  };
}

test("Duffel recovery performs only an authenticated exact-offer GET and verifies one test order", async () => {
  let request;
  const lookup = createDuffelOrderLookup({
    token: "duffel_test_secret",
    fetchImpl: async (url, options) => {
      request = { url, options };
      return { ok: true, status: 200, json: async () => ({ data: [verifiedOrder()], meta: { request_id: "req_1" } }) };
    },
  });
  const result = await lookup.findOrderForSession(session);
  assert.equal(result.status, "found");
  assert.equal(result.order.id, "ord_exact");
  assert.equal(request.options.method, "GET");
  assert.equal(request.options.headers.Authorization, "Bearer duffel_test_secret");
  assert.equal(request.url.searchParams.get("offer_id"), "off_exact");
  assert.equal(request.url.searchParams.get("limit"), "200");
});

test("zero, ambiguous, mismatched, or live Duffel orders never resolve unknown", async () => {
  for (const data of [
    [],
    [verifiedOrder(), verifiedOrder({ id: "ord_second" })],
    [verifiedOrder({ total_amount: "999.00" })],
    [verifiedOrder({ live_mode: true })],
  ]) {
    const lookup = createDuffelOrderLookup({
      token: "duffel_test_secret",
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ data }) }),
    });
    const result = await lookup.findOrderForSession(session);
    assert.notEqual(result.status, "found");
  }
});

test("Duffel recovery lookup has a bounded timeout", async () => {
  const lookup = createDuffelOrderLookup({
    token: "duffel_test_secret",
    timeoutMs: 5,
    fetchImpl: async (_url, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
    }),
  });
  await assert.rejects(lookup.findOrderForSession(session), (error) => error.name === "AbortError");
});
