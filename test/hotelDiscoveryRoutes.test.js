const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");

const serverPath = path.join(__dirname, "..", "server.js");
const serverRequire = createRequire(serverPath);
const jsonCopy = (value) => JSON.parse(JSON.stringify(value));
const noopMiddleware = () => (_req, _res, next) => next();

// Register the real server's middleware/routes without starting a socket, loading
// machine credentials, constructing database/payment clients, or using network.
// JWT cryptography is outside these route tests: a deterministic verifier lets us
// test the real optional/required-auth gates and ownership handoff independently.
function createServerHarness({ env = {}, providerResponse } = {}) {
  const layers = [];
  const providerCalls = [];
  const unexpectedCalls = [];
  const app = {
    set() {},
    listen() {},
    use(...args) {
      const mounted = typeof args[0] === "string" || Array.isArray(args[0]);
      const mounts = mounted ? [args.shift()].flat() : [""];
      layers.push({ mounts, handlers: args.flat(), method: null });
    },
  };
  for (const method of ["get", "post", "delete"]) {
    app[method] = (route, ...handlers) => layers.push({ mounts: [route], handlers, method: method.toUpperCase() });
  }
  const express = () => app;
  express.json = express.urlencoded = express.raw = noopMiddleware;
  class ForbiddenClient {
    constructor() { throw new Error("Route tests must not construct database or payment clients"); }
  }
  const context = {
    require(name) {
      if (name === "express") return express;
      if (name === "helmet") return noopMiddleware;
      if (name === "pg") return { Pool: ForbiddenClient };
      if (name === "stripe") return ForbiddenClient;
      if (name === "@google-cloud/translate") return { v2: { Translate: ForbiddenClient } };
      return serverRequire(name);
    },
    process: { env: { NODE_ENV: "test", AUTH_MODE: "prod", DUFFEL_STAYS_KEY: "duffel_test_fixture", JWT_SECRET: "route-test-only", ...env } },
    console: { log() {}, warn() {}, error() {} },
    URL, URLSearchParams, Buffer, TextEncoder, AbortController, setTimeout, clearTimeout,
    async fetch(url, options = {}) {
      // The server warms its display-FX cache on boot. Supply an empty local
      // response; this fixture never grants authority through an exchange rate.
      if (String(url) === "https://open.er-api.com/v6/latest/USD") {
        return { ok: true, status: 200, json: async () => ({}) };
      }
      const call = { url: String(url), options };
      providerCalls.push(call);
      if (providerResponse) {
        const result = await providerResponse(call);
        if (result !== undefined) {
          const status = result.httpStatus || 200;
          return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(result.httpStatus ? result.body : result) };
        }
      }
      unexpectedCalls.push(call.url);
      throw new Error("Unstubbed provider request rejected by route harness");
    },
  };
  vm.runInNewContext(`${fs.readFileSync(serverPath, "utf8")}\n
    getJose = async () => ({ jwtVerify: async (token) => {
      if (token !== "verified-fixture") throw new Error("Invalid fixture token");
      return { payload: { sub: "fixture-user" } };
    } });
    globalThis.testHooks = { hotelBookingService };
  `, context, { filename: serverPath });

  async function request(route, { method = "POST", body = {}, headers = {}, ip = "192.0.2.1" } = {}) {
    const req = { method, path: route, originalUrl: route, url: route, body, headers, ip, query: {}, params: {} };
    const response = { status: 200, body: null, headers: {}, finished: false };
    const res = {
      status(value) { response.status = value; return this; },
      json(value) { response.body = jsonCopy(value); response.finished = true; return this; },
      end() { response.finished = true; return this; },
      setHeader(name, value) { response.headers[name.toLowerCase()] = value; },
      getHeader(name) { return response.headers[name.toLowerCase()]; },
    };
    for (const layer of layers) {
      if (layer.method && layer.method !== method) continue;
      const mount = layer.mounts.find((entry) => {
        if (!layer.method) return !entry || route === entry || route.startsWith(`${entry}/`);
        return new RegExp(`^${entry.replace(/:[^/]+/g, "[^/]+")}$`).test(route);
      });
      if (mount === undefined) continue;
      req.path = layer.method ? route : (route.slice(mount.length) || "/");
      if (layer.method) {
        const names = mount.split("/");
        const values = route.split("/");
        names.forEach((part, index) => { if (part.startsWith(":")) req.params[part.slice(1)] = values[index]; });
      }
      for (const handler of layer.handlers) {
        let advanced = false;
        await handler(req, res, () => { advanced = true; });
        if (response.finished) return response;
        assert.equal(advanced, true, `Unfinished middleware for ${method} ${route}`);
      }
    }
    assert.fail(`No handler completed ${method} ${route}`);
  }
  return { request, providerCalls, unexpectedCalls, bookingService: context.testHooks.hotelBookingService };
}

function stayResult(overrides = {}) {
  return {
    id: "srr_fixture", check_in_date: "2026-10-15", check_out_date: "2026-10-22",
    rooms: 1, guests: [{ type: "adult" }, { type: "adult" }],
    expires_at: "2099-01-01T00:00:00Z",
    cheapest_rate_total_amount: "840.00", cheapest_rate_currency: "USD",
    accommodation: {
      id: "acc_fixture", name: "Fixture Hotel", photos: [{ url: "https://images.example/hotel.jpg" }],
      rooms: [{ name: "King room", rates: [
        { id: "rat_fixture", total_amount: "840.00", total_currency: "USD", base_amount: "700.00", base_currency: "USD",
          tax_amount: "100.00", tax_currency: "USD", fee_amount: "40.00", fee_currency: "USD",
          due_at_accommodation_amount: "20.00", due_at_accommodation_currency: "USD", expires_at: "2099-01-01T00:00:00Z" },
        { id: "rat_alternative", total_amount: "900.00", total_currency: "USD" },
      ] }],
    },
    ...overrides,
  };
}

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
