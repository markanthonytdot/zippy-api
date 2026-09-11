const test = require("node:test");
const assert = require("node:assert/strict");
const { createServerHarness, stayResult } = require("../test-support/hotelServerHarness");

const legacyPricesBody = {
  hotelIds: ["acc_fixture"], searchResultIds: { acc_fixture: "srr_fixture" },
  checkIn: "2026-10-15", nights: 7, adults: 2, rooms: 1, currency: "CAD",
};

test("anonymous hotel search and legacy room pricing retain their existing presentation contract", async () => {
  const harness = createServerHarness({ providerResponse: ({ url }) => url.endsWith("/stays/search") ? { data: { results: [stayResult()] } } : undefined });
  const search = await harness.request("/v1/hotels/search", { body: {
    city: "Miami", lat: 25.76, lng: -80.19, checkIn: "2026-10-15", nights: 7, adults: 2,
  } });
  assert.equal(search.status, 200);
  assert.equal(search.body.items[0].hotelId, "acc_fixture");
  assert.equal(search.body.items[0].searchResultId, "srr_fixture");
  assert.deepEqual(search.body.items[0].price, { total: "840.00", currency: "USD" });
  assert.equal(search.body.items[0].discoveryPrice, undefined);
  const prices = await harness.request("/v1/hotels/prices", { body: legacyPricesBody });
  assert.equal(prices.status, 200);
  assert.equal(prices.body.ok, true);
  assert.equal(prices.body.provider, "duffel");
  assert.deepEqual(prices.body.items.map((row) => [row.hotelId, row.price_status, row.price.total, row.price.currency, row.offer.id]), [
    ["acc_fixture", "priced", "840.00", "USD", "rat_fixture"],
    ["acc_fixture", "priced", "900.00", "USD", "rat_alternative"],
  ]);
  assert.equal(prices.body.items[0].offer.checkInDate, "2026-10-15");
  assert.equal(prices.body.items[0].offer.checkOutDate, "2026-10-22");
  assert.equal(prices.body.items[0].offer.adults, 2);
  assert.equal(prices.body.discoveryPrice, undefined);
  assert.equal(harness.providerCalls.length, 1, "Legacy room read still reuses its existing populated cache");
  assert.deepEqual(harness.unexpectedCalls, []);
});

test("anonymous room pricing can restore search continuity without authentication", async () => {
  const harness = createServerHarness({ providerResponse: ({ url }) => url.endsWith("/srr_fixture/actions/fetch_all_rates") ? { data: stayResult() } : undefined });
  const result = await harness.request("/v1/hotels/prices", { body: legacyPricesBody });
  assert.equal(result.status, 200);
  assert.equal(result.body.items[0].offer.id, "rat_fixture");
  assert.equal(harness.providerCalls.length, 1);
  assert.deepEqual(harness.unexpectedCalls, []);
});

test("anonymous hotel discovery keeps the existing hotel quota and strict CORS guard", async () => {
  const harness = createServerHarness({ env: { HOTELS_RPM: "1" } });
  const request = { body: { ...legacyPricesBody, searchResultIds: {} } };
  assert.equal((await harness.request("/v1/hotels/prices", request)).status, 200);
  const limited = await harness.request("/v1/hotels/prices", request);
  assert.equal(limited.status, 429);
  assert.match(limited.body.error, /Hotel rate limit/);
  const denied = await harness.request("/v1/hotels/prices", { method: "OPTIONS", headers: { origin: "https://unapproved.example" } });
  assert.equal(denied.status, 403);
  const preflight = await harness.request("/v1/hotels/prices", { method: "OPTIONS", headers: { origin: "https://www.heyzippi.com" } });
  assert.equal(preflight.status, 204);
  assert.match(preflight.headers["access-control-allow-headers"], /X-User-ID/);
  assert.equal(harness.providerCalls.length, 0);
});

const bookingRoutes = [
  ["POST", "/v1/hotels/quote", "quoteCheckout"],
  ["POST", "/v1/hotels/booking/sessions", "createSession"],
  ["POST", "/v1/hotels/booking/sessions/session-fixture/guest", "saveGuests"],
  ["POST", "/v1/hotels/booking/sessions/session-fixture/payment/setup", "paymentSetup"],
  ["POST", "/v1/hotels/booking/sessions/session-fixture/confirm", "confirm"],
  ["GET", "/v1/hotels/booking/sessions/session-fixture", "getStatus"],
];

test("hotel quotes and all booking/payment routes still reject anonymous, device-only and invalid bearer requests", async () => {
  const harness = createServerHarness({ env: { HOTELS_ROUTE_RPM: "100" } });
  for (const [, , action] of bookingRoutes) {
    harness.bookingService[action] = async () => assert.fail("Unverified caller reached a booking action");
  }
  for (const headers of [{}, { "x-user-id": "forged-account" }, { authorization: "Bearer invalid-fixture" }]) {
    for (const [method, route] of bookingRoutes) {
      const result = await harness.request(route, { method, headers });
      assert.equal(result.status, 401, `${method} ${route}`);
      assert.equal(result.body.ok, false);
    }
  }
  assert.equal(harness.providerCalls.length, 0);
});

test("verified booking requests retain existing authenticated action dispatch and account identity", async () => {
  const harness = createServerHarness();
  const calls = [];
  for (const [, , action] of bookingRoutes) {
    harness.bookingService[action] = async (...args) => { calls.push({ action, args }); return { ok: true, fixtureOnly: true }; };
  }
  for (const [method, route, action] of bookingRoutes) {
    const result = await harness.request(route, { method, headers: { authorization: "Bearer verified-fixture", "x-user-id": "forged-account" }, body: { fixture: true } });
    assert.equal(result.status, 200, action);
    assert.equal(calls.at(-1).action, action);
    if (action !== "quoteCheckout") assert.equal(calls.at(-1).args[0], "fixture-user");
  }
  assert.equal(calls.length, bookingRoutes.length);
  assert.equal(harness.providerCalls.length, 0);
});

const discoverySelection = {
  hotelId: "acc_fixture", searchResultId: "srr_fixture", rateId: "rat_fixture",
  checkIn: "2026-10-15", checkOut: "2026-10-22", adults: 2, rooms: 1, currency: "USD",
};
const discoveryBody = { discoveryPricing: discoverySelection };

test("anonymous opted-in discovery returns the exact complete rate in customer minor units", async () => {
  const harness = createServerHarness({ providerResponse: ({ url }) => url.endsWith("/srr_fixture/actions/fetch_all_rates") ? { data: stayResult() } : undefined });
  const result = await harness.request("/v1/hotels/prices", { body: discoveryBody });
  assert.equal(result.status, 200);
  assert.equal(result.body.ok, true);
  const price = result.body.discoveryPrice;
  assert.equal(price.version, 1);
  assert.equal(price.status, "authoritative");
  assert.deepEqual(price.selection, discoverySelection);
  assert.equal(price.customerCurrency, "USD");
  assert.equal(price.customerTotalMinor, 86000);
  assert.equal(Number.isSafeInteger(price.customerTotalMinor), true);
  assert.deepEqual(price.rateTotal, { currency: "USD", amountMinor: 84000 });
  assert.deepEqual(price.dueAtAccommodation, { currency: "USD", amountMinor: 2000 });
  assert.equal(price.taxes, "known_included");
  assert.equal(price.mandatoryFees, "known_included");
  assert.equal(price.propertyCharges, "known_additional");
  assert.equal(price.source, "duffel_fetch_all_rates");
  assert.equal(price.expiresAt, "2099-01-01T00:00:00.000Z");
  assert.ok(Number.isFinite(Date.parse(price.pricedAt)));
  assert.equal(result.body.items, undefined);
  assert.equal(harness.providerCalls.length, 1);
  assert.equal(harness.providerCalls[0].options.method, "POST");
  assert.deepEqual(harness.unexpectedCalls, []);
});

test("new discovery search/rate identity bypasses a populated legacy hotel/date cache on every read", async () => {
  const old = stayResult({ id: "srr_old" });
  old.accommodation.rooms[0].rates[0].id = "rat_old";
  const harness = createServerHarness({ providerResponse: ({ url }) => {
    if (url.endsWith("/stays/search")) return { data: { results: [old] } };
    if (url.endsWith("/srr_fixture/actions/fetch_all_rates")) return { data: stayResult() };
    return undefined;
  } });
  const search = await harness.request("/v1/hotels/search", { body: {
    city: "Miami", lat: 25.76, lng: -80.19, checkIn: "2026-10-15", nights: 7, adults: 2,
  } });
  assert.equal(search.body.items[0].searchResultId, "srr_old");
  const legacy = await harness.request("/v1/hotels/prices", { body: legacyPricesBody });
  assert.equal(legacy.body.items[0].offer.id, "rat_old");
  for (let index = 0; index < 2; index += 1) {
    const current = await harness.request("/v1/hotels/prices", { body: discoveryBody });
    assert.equal(current.body.discoveryPrice.status, "authoritative");
    assert.equal(current.body.discoveryPrice.selection.rateId, "rat_fixture");
  }
  assert.equal(harness.providerCalls.length, 3, "One search and a fresh exact-rate read for each discovery request");
  assert.deepEqual(harness.unexpectedCalls, []);
});

test("discovery cannot relabel a stale provider search result or a rate absent from that search", async () => {
  const harness = createServerHarness({ providerResponse: () => ({ data: stayResult({ id: "srr_old" }) }) });
  const staleSearch = await harness.request("/v1/hotels/prices", { body: discoveryBody });
  assert.equal(staleSearch.body.discoveryPrice.status, "identity_mismatch");
  assert.equal(staleSearch.body.discoveryPrice.customerTotalMinor, null);
  const missingRateHarness = createServerHarness({ providerResponse: () => ({ data: stayResult() }) });
  const missingRate = await missingRateHarness.request("/v1/hotels/prices", { body: {
    discoveryPricing: { ...discoverySelection, rateId: "rat_old" },
  } });
  assert.equal(missingRate.body.discoveryPrice.status, "identity_mismatch");
  assert.deepEqual(missingRate.body.discoveryPrice.reasons, ["rate_not_in_search_result"]);
  assert.equal(missingRate.body.discoveryPrice.customerTotalMinor, null);
});

test("discovery returns explicit non-authority for currency mismatch and missing property charges", async () => {
  const harness = createServerHarness({ providerResponse: () => ({ data: stayResult() }) });
  const incompatible = await harness.request("/v1/hotels/prices", { body: {
    discoveryPricing: { ...discoverySelection, currency: "CAD" },
  } });
  assert.equal(incompatible.body.discoveryPrice.status, "incompatible_currency");
  assert.equal(incompatible.body.discoveryPrice.customerCurrency, "CAD");
  assert.equal(incompatible.body.discoveryPrice.customerTotalMinor, null);
  const unknown = stayResult();
  unknown.accommodation.rooms[0].rates[0].due_at_accommodation_amount = null;
  const incompleteHarness = createServerHarness({ providerResponse: () => ({ data: unknown }) });
  const incomplete = await incompleteHarness.request("/v1/hotels/prices", { body: discoveryBody });
  assert.equal(incomplete.body.discoveryPrice.status, "incomplete");
  assert.equal(incomplete.body.discoveryPrice.propertyCharges, "unknown");
  assert.equal(incomplete.body.discoveryPrice.customerTotalMinor, null);
});

test("expired provider data and expired continuity responses require refresh", async () => {
  const expiredHarness = createServerHarness({ providerResponse: () => ({ data: stayResult({ expires_at: "2020-01-01T00:00:00Z" }) }) });
  const expired = await expiredHarness.request("/v1/hotels/prices", { body: discoveryBody });
  assert.equal(expired.body.discoveryPrice.status, "refresh_needed");
  assert.equal(expired.body.discoveryPrice.customerTotalMinor, null);
  for (const httpStatus of [404, 410, 422]) {
    const harness = createServerHarness({ providerResponse: () => ({ httpStatus, body: { errors: [{ code: "not_found" }] } }) });
    const result = await harness.request("/v1/hotels/prices", { body: discoveryBody });
    assert.equal(result.status, 200);
    assert.equal(result.body.discoveryPrice.status, "refresh_needed", String(httpStatus));
    assert.equal(result.body.discoveryPrice.customerTotalMinor, null);
  }
});

test("provider pricing failures stay read-only and do not grant subsequent booking access", async () => {
  const harness = createServerHarness({ providerResponse: () => ({ httpStatus: 503, body: { errors: [{ code: "temporarily_unavailable" }] } }) });
  const result = await harness.request("/v1/hotels/prices", { body: discoveryBody });
  assert.equal(result.body.discoveryPrice.status, "unavailable");
  assert.equal(result.body.discoveryPrice.customerTotalMinor, null);
  assert.equal((await harness.request("/v1/hotels/booking/sessions", { body: discoveryBody })).status, 401);
  assert.equal(harness.providerCalls.length, 1);
});

test("invalid discovery requests cannot fall back to legacy cached/display prices", async () => {
  const harness = createServerHarness();
  for (const discoveryPricing of [null, {}, { ...discoverySelection, rooms: 2 }, { ...discoverySelection, nights: 7 }]) {
    const result = await harness.request("/v1/hotels/prices", { body: { ...legacyPricesBody, discoveryPricing } });
    assert.equal(result.status, 400);
    assert.equal(result.body.ok, false);
    assert.equal(result.body.items, undefined);
  }
  assert.equal(harness.providerCalls.length, 0);
});
