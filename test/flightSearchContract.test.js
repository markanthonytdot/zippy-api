const test = require("node:test");
const assert = require("node:assert/strict");

const {
  BEST_RANKING_METHOD,
  CONTRACT_VERSION,
  buildFlightSearchContract,
  parseDurationMinutes,
} = require("../lib/flightSearchContract");

function passenger(checked = 1, cabinCarryOn = 1, personalItems = 0) {
  return { baggages: [
    { type: "checked", quantity: checked },
    { type: "carry_on", quantity: cabinCarryOn },
    { type: "personal_item", quantity: personalItems },
  ] };
}

function segment(origin, destination, departure, arrival, passengers = [passenger()]) {
  return {
    departing_at: departure,
    arriving_at: arrival,
    origin: { iata_code: origin, name: `${origin} Airport` },
    destination: { iata_code: destination, name: `${destination} Airport` },
    marketing_carrier: { name: "Zippi Test Air" },
    marketing_carrier_flight_number: "101",
    passengers,
  };
}

function offer(id, amount, durations) {
  const outbound = segment("YYZ", "MIA", "2026-09-10T12:00:00Z", "2026-09-10T15:00:00Z");
  const inbound = segment("MIA", "YYZ", "2026-09-17T16:00:00Z", "2026-09-17T19:00:00Z");
  return {
    id,
    total_amount: amount,
    total_currency: "CAD",
    passengers: [{ id: "pas_1" }],
    slices: durations.map((duration, index) => ({ duration, segments: [index ? inbound : outbound] })),
    cabin_class: "economy",
    fare_brand_name: "Standard",
  };
}

test("normalizes provider offers while preserving canonical atomic round trips", () => {
  const raw = offer("off_round_trip", "420.50", ["PT3H10M", "PT3H20M"]);
  const contract = buildFlightSearchContract([raw]);

  assert.equal(contract.contractVersion, CONTRACT_VERSION);
  assert.equal(contract.rankingMethod, BEST_RANKING_METHOD);
  assert.equal(contract.rankingCurrency, "CAD");
  assert.equal(contract.offers[0].id, raw.id);
  assert.equal(contract.offers[0].totalAmount, "420.50");
  assert.equal(contract.offers[0].slices.length, 2);
  assert.equal(contract.offers[0].slices[1].segments[0].destination.iataCode, "YYZ");
  assert.equal(contract.offers[0].totalDurationMinutes, 390);
  assert.deepEqual(contract.offers[0].baggage, {
    minimumCheckedPerTraveler: 1,
    minimumCabinCarryOnPerTraveler: 1,
    minimumPersonalItemsPerTraveler: 0,
    complete: true,
    heterogeneous: false,
  });
  assert.deepEqual(contract.rankings, {
    best: [raw.id], cheapest: [raw.id], fastest: [raw.id],
  });
  assert.deepEqual(contract.rankingAvailability, { best: true, cheapest: true, fastest: true });
});

test("owns deterministic Best, Cheapest, and Fastest ranking independent of provider order", () => {
  const cheapSlow = offer("off_cheap_slow", "100.00", ["PT5H"]);
  const balanced = offer("off_balanced", "130.00", ["PT2H"]);
  const fastExpensive = offer("off_fast_expensive", "300.00", ["PT1H"]);

  const forward = buildFlightSearchContract([fastExpensive, cheapSlow, balanced]);
  const reversed = buildFlightSearchContract([balanced, cheapSlow, fastExpensive]);
  assert.deepEqual(forward.rankings, reversed.rankings);
  assert.deepEqual(forward.rankings.cheapest, ["off_cheap_slow", "off_balanced", "off_fast_expensive"]);
  assert.deepEqual(forward.rankings.fastest, ["off_fast_expensive", "off_balanced", "off_cheap_slow"]);
  assert.deepEqual(forward.rankings.best, ["off_balanced", "off_cheap_slow", "off_fast_expensive"]);
});

test("uses canonical IDs for ties, de-duplicates page overlaps, and ranks missing facts last", () => {
  const sameA = offer("off_a", "100.00", ["PT2H"]);
  const sameB = offer("off_b", "100.00", ["PT2H"]);
  const incomplete = offer("off_missing", "not-a-price", ["not-a-duration"]);
  incomplete.slices[0].segments = [];
  const contract = buildFlightSearchContract([sameB, incomplete, sameA, sameA, { id: "" }]);

  assert.deepEqual(contract.offers.map((item) => item.id), ["off_b", "off_missing", "off_a"]);
  assert.deepEqual(contract.rankings.cheapest, ["off_a", "off_b", "off_missing"]);
  assert.deepEqual(contract.rankings.fastest, ["off_a", "off_b", "off_missing"]);
  assert.deepEqual(contract.rankings.best, ["off_a", "off_b", "off_missing"]);
  assert.equal(contract.offers.find((item) => item.id === "off_missing").totalAmount, null);
  assert.equal(contract.offers.find((item) => item.id === "off_missing").totalDurationMinutes, null);
});

test("parses Duffel ISO durations including day components", () => {
  assert.equal(parseDurationMinutes("PT12H25M"), 745);
  assert.equal(parseDurationMinutes("P1DT2H5M"), 1565);
  assert.equal(parseDurationMinutes("P"), null);
  assert.equal(parseDurationMinutes("PT"), null);
  assert.equal(parseDurationMinutes("invalid"), null);
});

test("uses timestamp fallback only when both timestamps carry explicit offsets", () => {
  const explicit = offer("off_explicit", "100.00", ["invalid"]);
  assert.equal(buildFlightSearchContract([explicit]).offers[0].totalDurationMinutes, 180);

  const explicitOffset = offer("off_offset", "100.00", ["invalid"]);
  explicitOffset.slices[0].segments[0].departing_at = "2026-09-10T12:00:00-04:00";
  explicitOffset.slices[0].segments[0].arriving_at = "2026-09-10T15:30:00-04:00";
  assert.equal(buildFlightSearchContract([explicitOffset]).offers[0].totalDurationMinutes, 210);

  const localTime = offer("off_local", "100.00", ["invalid"]);
  localTime.slices[0].segments[0].departing_at = "2026-09-10T12:00:00";
  localTime.slices[0].segments[0].arriving_at = "2026-09-10T15:00:00";
  assert.equal(buildFlightSearchContract([localTime]).offers[0].totalDurationMinutes, null);
});

test("reports minimum per-traveler baggage and whether complete allowances vary", () => {
  const varied = offer("off_varied_bags", "100.00", ["PT3H"]);
  varied.passengers.push({ id: "pas_2" });
  varied.slices[0].segments[0].passengers = [passenger(1, 1), passenger(0, 2)];
  assert.deepEqual(buildFlightSearchContract([varied]).offers[0].baggage, {
    minimumCheckedPerTraveler: 0,
    minimumCabinCarryOnPerTraveler: 1,
    minimumPersonalItemsPerTraveler: 0,
    complete: true,
    heterogeneous: true,
  });

  delete varied.slices[0].segments[0].passengers[1].baggages;
  assert.deepEqual(buildFlightSearchContract([varied]).offers[0].baggage, {
    minimumCheckedPerTraveler: null,
    minimumCabinCarryOnPerTraveler: null,
    minimumPersonalItemsPerTraveler: null,
    complete: false,
    heterogeneous: null,
  });
});

test("uses price eligibility for Best/Cheapest and duration eligibility for Fastest across currencies", () => {
  const cadSlow = offer("off_cad_slow", "200.00", ["PT5H"]);
  const cadFast = offer("off_cad_fast", "250.00", ["PT2H"]);
  const usdCheapFast = offer("off_usd", "1.00", ["PT1H"]);
  usdCheapFast.total_currency = "USD";

  const contract = buildFlightSearchContract([usdCheapFast, cadSlow, cadFast], "cad");
  assert.equal(contract.rankingCurrency, "CAD");
  assert.deepEqual(contract.offers.find((item) => item.id === "off_usd").rankingEligibility, {
    best: false, cheapest: false, fastest: true,
  });
  assert.deepEqual(contract.rankings.cheapest, ["off_cad_slow", "off_cad_fast", "off_usd"]);
  assert.deepEqual(contract.rankings.fastest, ["off_usd", "off_cad_fast", "off_cad_slow"]);
  assert.equal(contract.rankings.best.at(-1), "off_usd");
  assert.deepEqual(contract.rankingAvailability, { best: true, cheapest: true, fastest: true });

  const noCommonCurrency = buildFlightSearchContract([usdCheapFast, cadSlow]);
  assert.equal(noCommonCurrency.rankingCurrency, null);
  assert.ok(noCommonCurrency.offers.every((item) => !item.rankingEligibility.best && !item.rankingEligibility.cheapest));
  assert.deepEqual(noCommonCurrency.rankings.cheapest, ["off_cad_slow", "off_usd"]);
  assert.deepEqual(noCommonCurrency.rankings.fastest, ["off_usd", "off_cad_slow"]);
  assert.deepEqual(noCommonCurrency.rankingAvailability, { best: false, cheapest: false, fastest: true });
});

test("personal items are not reported as cabin carry-ons", () => {
  const personalItemOnly = offer("off_personal_item", "100.00", ["PT2H"]);
  personalItemOnly.slices[0].segments[0].passengers = [passenger(0, 0, 1)];
  assert.deepEqual(buildFlightSearchContract([personalItemOnly]).offers[0].baggage, {
    minimumCheckedPerTraveler: 0,
    minimumCabinCarryOnPerTraveler: 0,
    minimumPersonalItemsPerTraveler: 1,
    complete: true,
    heterogeneous: false,
  });
});

test("marks price modes unavailable when no valid price exists while retaining Fastest", () => {
  const invalidPrice = offer("off_invalid_price", "", ["PT2H"]);
  const contract = buildFlightSearchContract([invalidPrice], "CAD");
  assert.deepEqual(contract.offers[0].rankingEligibility, { best: false, cheapest: false, fastest: true });
  assert.deepEqual(contract.rankingAvailability, { best: false, cheapest: false, fastest: true });
});

test("requires known duration for Best but not Cheapest", () => {
  const missingDuration = offer("off_missing_duration", "100.00", ["invalid"]);
  missingDuration.slices[0].segments = [];
  const contract = buildFlightSearchContract([missingDuration], "CAD");
  assert.deepEqual(contract.offers[0].rankingEligibility, { best: false, cheapest: true, fastest: false });
  assert.deepEqual(contract.rankingAvailability, { best: false, cheapest: true, fastest: false });
});

test("does not expose a normalized price claim without a valid currency", () => {
  const missingCurrency = offer("off_missing_currency", "100.00", ["PT2H"]);
  missingCurrency.total_currency = "";
  const contract = buildFlightSearchContract([missingCurrency], "CAD");
  assert.equal(contract.offers[0].totalAmount, null);
  assert.equal(contract.offers[0].totalCurrency, null);
  assert.deepEqual(contract.offers[0].rankingEligibility, { best: false, cheapest: false, fastest: true });
});
