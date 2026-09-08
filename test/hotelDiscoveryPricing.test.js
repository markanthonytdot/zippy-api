const test = require("node:test");
const assert = require("node:assert/strict");
const { validateDiscoverySelection, projectHotelDiscoveryPrice, createHotelDiscoveryPricingHandler } = require("../lib/hotelDiscoveryPricing");

const now = Date.parse("2026-09-07T23:00:00Z");
const selection = Object.freeze({ hotelId: "acc_miami", searchResultId: "srr_current", rateId: "rat_selected",
  checkIn: "2026-10-15", checkOut: "2026-10-22", adults: 2, rooms: 1, currency: "CAD" });

// Synthetic values following Duffel's documented raw fetch_all_rates schema.
// This fixture is not a captured supplier quote or a real availability assertion.
function providerResult() {
  return {
    id: selection.searchResultId, check_in_date: selection.checkIn, check_out_date: selection.checkOut,
    rooms: 1, guests: [{ type: "adult" }, { type: "adult" }], expires_at: "2026-09-07T23:20:00Z",
    accommodation: { id: selection.hotelId, rooms: [{ name: "King room", rates: [{
      id: selection.rateId, expires_at: "2026-09-07T23:10:00Z", payment_type: "pay_now",
      total_amount: "912.34", total_currency: "CAD", base_amount: "800.00", base_currency: "CAD",
      tax_amount: "100.00", tax_currency: "CAD", fee_amount: "12.34", fee_currency: "CAD",
      due_at_accommodation_amount: "40.01", due_at_accommodation_currency: "CAD",
    }] }] },
  };
}
const rate = (result) => result.accommodation.rooms[0].rates[0];
const project = (result = providerResult(), request = selection, options = {}) => projectHotelDiscoveryPrice(result, request, { now, ...options });

test("exact property/search-result/rate/stay/adult occupancy and one room survive projection", () => {
  const output = project();
  assert.equal(output.status, "authoritative");
  assert.deepEqual(output.selection, selection);
  assert.equal(output.customerCurrency, "CAD");
  assert.equal(output.customerTotalMinor, 95_235);
  assert.equal(Number.isSafeInteger(output.customerTotalMinor), true);
  assert.equal(output.source, "duffel_fetch_all_rates");
  assert.equal(output.pricedAt, new Date(now).toISOString());
  assert.equal(output.expiresAt, "2026-09-07T23:10:00.000Z");
});

test("included taxes and fees are not added twice; mandatory property amount is added once", () => {
  const output = project();
  assert.equal(output.taxes, "known_included");
  assert.equal(output.mandatoryFees, "known_included");
  assert.equal(output.propertyCharges, "known_additional");
  assert.deepEqual(output.rateTotal, { currency: "CAD", amountMinor: 91_234 });
  assert.deepEqual(output.dueAtAccommodation, { currency: "CAD", amountMinor: 4_001 });
  assert.equal(output.customerTotalMinor, 91_234 + 4_001);
});

test("known zero property charges qualify and are distinct from unknown", () => {
  const result = providerResult();
  rate(result).due_at_accommodation_amount = "0.00";
  assert.equal(project(result).customerTotalMinor, 91_234);
  for (const unknown of [undefined, null, "", -1, "-1.00"]) {
    rate(result).due_at_accommodation_amount = unknown;
    const output = project(result);
    assert.equal(output.status, "incomplete");
    assert.equal(output.customerTotalMinor, null);
    assert.equal(output.propertyCharges, "unknown");
  }
});

test("exact decimal parsing avoids binary rounding and accepts trailing zero precision only", () => {
  const result = providerResult();
  Object.assign(rate(result), { base_amount: "0.10", tax_amount: "0.20", fee_amount: "0.0000", total_amount: "0.3000", due_at_accommodation_amount: "0.010" });
  assert.equal(project(result).customerTotalMinor, 31);
  rate(result).total_amount = "0.301";
  assert.equal(project(result).customerTotalMinor, null);
});

test("numeric, exponential, negative, nonfinite and overflowing supplier amounts fail closed", () => {
  for (const bad of [912.34, "9e2", "-1.00", "Infinity", "NaN", "9007199254740993.00"]) {
    const result = providerResult(); rate(result).total_amount = bad;
    assert.equal(project(result).customerTotalMinor, null, String(bad));
  }
  const result = providerResult();
  Object.assign(rate(result), { total_amount: "90071992547409.91", base_amount: "90071992547409.91", tax_amount: "0", fee_amount: "0", due_at_accommodation_amount: "0.01" });
  assert.deepEqual(project(result).reasons, ["customer_total_overflow"]);
});

test("provider currency mismatch is explicit and no FX is attempted", () => {
  for (const field of ["total_currency", "base_currency", "tax_currency", "fee_currency", "due_at_accommodation_currency"]) {
    const result = providerResult(); rate(result)[field] = "USD";
    const output = project(result);
    assert.equal(output.status, "incompatible_currency", field);
    assert.equal(output.customerCurrency, "CAD");
    assert.equal(output.customerTotalMinor, null);
  }
});

test("missing component/property currencies are not guessed, including zero property amount", () => {
  for (const field of ["total_currency", "base_currency", "tax_currency", "fee_currency", "due_at_accommodation_currency"]) {
    const result = providerResult(); rate(result)[field] = null;
    rate(result).due_at_accommodation_amount = "0.00";
    assert.equal(project(result).customerTotalMinor, null, field);
  }
});

test("base/public/search-card and nightly-times-nights cannot replace the exact rate total", () => {
  const result = providerResult();
  delete rate(result).total_amount;
  rate(result).public_amount = "912.34";
  rate(result).nightly_amount = "130.334285714";
  result.cheapest_rate_total_amount = "912.34";
  result.price = { total: "912.34", currency: "CAD" };
  assert.equal(project(result).customerTotalMinor, null);
  assert.ok(project(result).reasons.includes("rate_total_unknown"));
});

test("missing tax/fee breakdown stays unknown even with invented inclusion booleans", () => {
  for (const field of ["base_amount", "tax_amount", "fee_amount"]) {
    const result = providerResult(); delete rate(result)[field];
    Object.assign(rate(result), { taxesIncluded: true, mandatoryFeesComplete: true });
    const output = project(result);
    assert.equal(output.customerTotalMinor, null);
    assert.equal(output.taxes, "unknown");
    assert.equal(output.mandatoryFees, "unknown");
  }
});

test("inconsistent breakdown cannot establish included coverage", () => {
  const result = providerResult(); rate(result).tax_amount = "90.00";
  assert.deepEqual(project(result).reasons, ["rate_breakdown_inconsistent"]);
  assert.equal(project(result).taxes, "unknown");
});

test("payment timing does not change total or add deposits/remainders again", () => {
  for (const payment_type of ["pay_now", "deposit", "guarantee"]) {
    const result = providerResult(); rate(result).payment_type = payment_type;
    assert.equal(project(result).customerTotalMinor, 95_235);
  }
});

test("mismatched property/search-result/dates/guests/rooms cannot be relabelled as requested stay", () => {
  const mutations = [
    (r) => { r.id = "srr_old"; }, (r) => { r.accommodation.id = "acc_other"; },
    (r) => { r.check_in_date = "2026-10-16"; }, (r) => { r.check_out_date = "2026-10-23"; },
    (r) => { delete r.check_in_date; }, (r) => { r.guests.pop(); },
    (r) => { r.guests[1] = { type: "child", age: 8 }; }, (r) => { r.rooms = 2; },
  ];
  for (const mutate of mutations) {
    const result = providerResult(); mutate(result);
    assert.equal(project(result).status, "identity_mismatch");
    assert.equal(project(result).customerTotalMinor, null);
  }
});

test("missing, stale and ambiguous rate IDs fail instead of choosing first or cheapest rate", () => {
  const result = providerResult();
  assert.equal(project(result, { ...selection, rateId: "rat_old" }).status, "identity_mismatch");
  result.accommodation.rooms.push({ rates: [{ ...rate(result) }] });
  assert.deepEqual(project(result).reasons, ["ambiguous_rate_identity"]);
});

test("earlier search expiry wins; expiry equality explicitly requires refresh", () => {
  const result = providerResult(); result.expires_at = "2026-09-07T23:01:00Z";
  assert.equal(project(result).expiresAt, "2026-09-07T23:01:00.000Z");
  assert.equal(project(result, selection, { now: now + 60_000 }).status, "refresh_needed");
  assert.equal(project(result, selection, { now: now + 60_001 }).customerTotalMinor, null);
});

test("missing/malformed provider expiry fails despite cached/priced flags or recent retrieval timestamp", () => {
  for (const expiry of [undefined, null, "2026-02-30T23:20:00Z", "tomorrow", "2026-09-07T25:20:00Z", "2026-09-07T23:20:00Z\n"]) {
    const result = providerResult(); rate(result).expires_at = expiry;
    Object.assign(result, { cached: true, price_status: "priced", updatedAt: new Date(now).toISOString() });
    assert.equal(project(result).status, "refresh_needed");
    assert.equal(project(result).customerTotalMinor, null);
  }
  const result = providerResult(); delete result.expires_at;
  assert.equal(project(result).status, "refresh_needed");
});

test("selection validates exact dates and supported one-room adult occupancy without clamping", () => {
  assert.deepEqual(validateDiscoverySelection(selection), selection);
  for (const patch of [
    { checkIn: "2026-02-30" }, { checkOut: "2026-10-15" }, { checkOut: "2026-11-15" },
    { adults: 0 }, { adults: 10 }, { adults: 1.5 }, { adults: "2" }, { rooms: 2 }, { rooms: "1" },
    { children: 1 }, { rateId: "" }, { rateId: "rat_selected\n" }, { currency: "cad" }, { currency: "CAD\n" },
  ]) assert.equal(validateDiscoverySelection({ ...selection, ...patch }), null, JSON.stringify(patch));
});

test("all supported requested currencies preserve exact native amounts; disabled currencies reject", () => {
  for (const currency of ["CAD", "USD", "EUR", "COP"]) {
    const result = providerResult();
    for (const field of ["total_currency", "base_currency", "tax_currency", "fee_currency", "due_at_accommodation_currency"]) rate(result)[field] = currency;
    assert.equal(project(result, { ...selection, currency }).customerTotalMinor, 95_235);
  }
  assert.equal(project(providerResult(), selection, { enabledCurrencies: ["USD"] }).status, "incompatible_currency");
});

async function invokeHandler({ request = selection, fetchRates = async () => ({ ok: true, result: providerResult() }), getEnabledCurrencies = async () => ["CAD"] } = {}) {
  const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  await createHotelDiscoveryPricingHandler({ fetchRates, getEnabledCurrencies, now: () => now })({ body: { discoveryPricing: request }, requestId: "request_fixture" }, res);
  return res;
}

test("handler performs fresh read by exact search-result ID without auth or booking operations", async () => {
  let calls = 0;
  const fetchRates = async (args) => { calls++; assert.deepEqual(args, { searchResultId: "srr_current", requestId: "request_fixture" }); return { ok: true, result: providerResult() }; };
  assert.equal((await invokeHandler({ fetchRates })).body.discoveryPrice.status, "authoritative");
  assert.equal((await invokeHandler({ fetchRates })).body.discoveryPrice.status, "authoritative");
  assert.equal(calls, 2);
});

test("invalid requests and unsupported currency do not call the provider", async () => {
  const fetchRates = async () => { assert.fail("Provider must not be called"); };
  assert.equal((await invokeHandler({ request: { ...selection, rooms: 2 }, fetchRates })).statusCode, 400);
  const unsupported = await invokeHandler({ request: { ...selection, currency: "GBP" }, fetchRates });
  assert.equal(unsupported.body.discoveryPrice.status, "incompatible_currency");
});

test("expired provider search gives explicit refresh-needed and technical failures stay private", async () => {
  for (const providerStatus of [404, 410, 422]) {
    const response = await invokeHandler({ fetchRates: async () => ({ ok: false, status: 502, providerStatus, error: "secret upstream detail" }) });
    assert.equal(response.body.discoveryPrice.status, "refresh_needed");
    assert.ok(!JSON.stringify(response.body).includes("secret"));
  }
  const response = await invokeHandler({ fetchRates: async () => { throw new Error("secret"); } });
  assert.equal(response.body.discoveryPrice.status, "unavailable");
  assert.ok(!JSON.stringify(response.body).includes("secret"));
});

test("currency configuration failure has explicit unavailable state", async () => {
  const output = await invokeHandler({ getEnabledCurrencies: async () => null });
  assert.deepEqual(output.body.discoveryPrice.reasons, ["currency_configuration_unavailable"]);
});
