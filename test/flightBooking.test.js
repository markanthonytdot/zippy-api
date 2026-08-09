const test = require("node:test");
const assert = require("node:assert/strict");
const {
  buildConfirmation,
  buildDuffelPassengers,
  buildPricingQuote,
  calculatePricing,
  createFlightBookingService,
  decimalToMinor,
  isDefinitiveDuffelOrderFailureStatus,
  minorToDecimal,
  normalizeAvailableServices,
  requestedServiceQuantities,
  resolveSelectedServices,
  staleBookingClaimDisposition,
  validateCheckoutPayload,
  validateInternationalTravelerDocuments,
  validateTravelerTypesForOffer,
} = require("../lib/flightBooking");

function validPayload(overrides = {}) {
  return {
    offerId: "off_test",
    returnOfferId: null,
    currency: "USD",
    totalMinor: 12_500,
    baggageServiceIds: [],
    travelers: [{
      travelerType: "adult",
      title: "Mr",
      firstName: "Test",
      middleName: null,
      lastName: "Traveler",
      gender: "Male",
      dateOfBirthISO: "1987-07-24",
    }],
    contact: { email: "test@example.com", phone: "+14165551234" },
    ...overrides,
  };
}

function pricingConfig(overrides = {}) {
  return {
    zippiFeeMinor: 499,
    fxMarginBps: 500,
    zippiMarkupBps: 0,
    minGrossMarginMinor: 0,
    paymentProcessingPercentBps: 0,
    paymentProcessingFixedMinor: 0,
    paymentProcessingCrossBorderBps: 0,
    ...overrides,
  };
}

test("converts provider decimal prices without floating point arithmetic", () => {
  assert.equal(decimalToMinor("120.00", "USD"), 12_000);
  assert.equal(decimalToMinor("120", "JPY"), 120);
  assert.equal(decimalToMinor("1.234", "KWD"), 1_234);
  assert.equal(minorToDecimal(12_345, "USD"), "123.45");
});

test("checkout validation accepts one atomic round-trip offer and rejects mixed offers", () => {
  assert.equal(validateCheckoutPayload(validPayload({ returnOfferId: "off_test" })).returnOfferId, "off_test");
  assert.throws(
    () => validateCheckoutPayload(validPayload({ returnOfferId: "off_return" })),
    (error) => error.code === "atomic_round_trip_required"
  );
  assert.throws(() => validateCheckoutPayload(validPayload({ contact: { email: "test@example.com", phone: "4165551234" } })), /international format/i);
  assert.throws(() => validateCheckoutPayload(validPayload({ bookingSessionId: "not-a-uuid" })), /session ID is invalid/i);
});

test("available services are normalized and filtered for existing iOS decoders", () => {
  const raw = [
    {
      id: "ase_bag",
      type: "baggage",
      maximum_quantity: 2,
      total_amount: "25.00",
      total_currency: "USD",
      metadata: { type: "checked", maximum_weight_kg: 23 },
    },
    {
      id: "ase_cfar",
      type: "cancel_for_any_reason",
      total_amount: "12.00",
      total_currency: "USD",
      metadata: { coverage_percentage: 80, expires_at: "2026-08-09T00:00:00Z" },
    },
  ];

  const baggage = normalizeAvailableServices(raw, "baggage");
  assert.equal(baggage.length, 1);
  assert.equal(baggage[0].type, "checked");
  assert.equal(baggage[0].maximum_quantity, 2);

  const cfar = normalizeAvailableServices(raw, "cancel_for_any_reason");
  assert.equal(cfar.length, 1);
  assert.equal(cfar[0].coverage_percentage, 80);
  assert.equal(cfar[0].expires_at, "2026-08-09T00:00:00Z");
});

test("repeated baggage IDs preserve the selected Duffel quantity", () => {
  const payload = validPayload({
    baggageServiceIds: ["ase_bag", "ase_bag"],
    seatServiceId: "ase_seat",
  });
  const quantities = requestedServiceQuantities(payload);
  assert.equal(quantities.get("ase_bag"), 2);
  assert.equal(quantities.get("ase_seat"), 1);

  const offer = {
    available_services: [{ id: "ase_bag", total_amount: "25.00", total_currency: "USD", maximum_quantity: 2 }],
  };
  const seatMaps = [{ cabins: [{ rows: [{ sections: [{ elements: [{
    available_services: [{ id: "ase_seat", total_amount: "8.00", total_currency: "USD" }],
  }] }] }] }] }];
  const services = resolveSelectedServices(payload, offer, seatMaps);
  const pricing = calculatePricing({
    base_amount: "100.00",
    tax_amount: "20.00",
    total_amount: "120.00",
    total_currency: "USD",
  }, services, "USD", pricingConfig(), { base: "USD", rates: { USD: 1 }, source: "test" });
  assert.deepEqual(services.map(({ id, quantity }) => ({ id, quantity })), [
    { id: "ase_bag", quantity: 2 },
    { id: "ase_seat", quantity: 1 },
  ]);
  assert.equal(pricing.providerTotalMinor, 17_800);
  assert.equal(pricing.customerTotalMinor, 18_500);
  assert.deepEqual(buildPricingQuote(pricing).lineItems, {
    baseFareMinor: 10_000,
    taxesMinor: 2_000,
    servicesMinor: 5_800,
    zippiFeeMinor: 499,
    preRoundMinor: 18_299,
    roundingAdjustmentMinor: 201,
  });
});

test("two-sided pricing converts the provider total, adds the fee, and rounds up in customer currency", () => {
  const pricing = calculatePricing({
    base_amount: "300.00",
    tax_amount: "80.00",
    total_amount: "380.00",
    total_currency: "USD",
  }, [], "CAD", pricingConfig(), { base: "USD", rates: { USD: 1, CAD: 1.35 }, source: "test" });

  assert.equal(pricing.providerCurrency, "USD");
  assert.equal(pricing.providerTotalMinor, 38_000);
  assert.equal(pricing.customerCurrency, "CAD");
  assert.equal(pricing.customerFxMarginBps, 500);
  assert.equal(pricing.customerConvertedMinor, 53_865);
  assert.equal(pricing.customerPreRoundMinor, 54_364);
  assert.equal(pricing.customerTotalMinor, 54_500);
  assert.equal(pricing.customerRoundingAdjustmentMinor, 136);
});

test("exact five-unit customer totals remain unchanged after rounding", () => {
  const pricing = calculatePricing({
    base_amount: "95.01",
    tax_amount: "0.00",
    total_amount: "95.01",
    total_currency: "USD",
  }, [], "USD", pricingConfig(), { base: "USD", rates: { USD: 1 }, source: "test" });

  assert.equal(pricing.customerPreRoundMinor, 10_000);
  assert.equal(pricing.customerTotalMinor, 10_000);
  assert.equal(pricing.customerRoundingAdjustmentMinor, 0);
  assert.equal(pricing.providerTotalMinor, 9_501);
});

test("pricing protection layer adds markup, processing allowance, and minimum-margin enforcement", () => {
  const pricing = calculatePricing({
    base_amount: "200.00",
    tax_amount: "0.00",
    total_amount: "200.00",
    total_currency: "USD",
  }, [], "USD", pricingConfig({
    zippiMarkupBps: 700,
    minGrossMarginMinor: 1_599,
    paymentProcessingPercentBps: 350,
    paymentProcessingFixedMinor: 30,
  }), { base: "USD", rates: { USD: 1 }, source: "test" });

  assert.equal(pricing.customerRawConvertedMinor, 20_000);
  assert.equal(pricing.customerFxProtectionMinor, 0);
  assert.equal(pricing.customerZippiMarkupMinor, 1_400);
  assert.equal(pricing.customerMinMarginTopUpMinor, 0);
  assert.equal(pricing.customerPaymentProcessingAllowanceMinor, 826);
  assert.equal(pricing.customerPreRoundMinor, 22_725);
  assert.equal(pricing.customerTotalMinor, 23_000);
  assert.equal(pricing.customerEstimatedProcessingMinor, 835);
  assert.equal(pricing.customerEstimatedGrossMarginMinor, 2_165);
});

test("cross-currency pricing keeps FX protection separate from markup and processing coverage", () => {
  const pricing = calculatePricing({
    base_amount: "200.00",
    tax_amount: "0.00",
    total_amount: "200.00",
    total_currency: "USD",
  }, [], "CAD", pricingConfig({
    zippiMarkupBps: 700,
    minGrossMarginMinor: 1_599,
    paymentProcessingPercentBps: 350,
    paymentProcessingFixedMinor: 30,
  }), { base: "USD", rates: { USD: 1, CAD: 1.4 }, source: "test" });

  assert.equal(pricing.customerRawConvertedMinor, 28_000);
  assert.equal(pricing.customerFxProtectionMinor, 1_400);
  assert.equal(pricing.customerConvertedMinor, 29_400);
  assert.equal(pricing.customerZippiMarkupMinor, 2_058);
  assert.equal(pricing.customerMinMarginTopUpMinor, 0);
  assert.equal(pricing.customerPaymentProcessingAllowanceMinor, 1_191);
  assert.equal(pricing.customerTotalMinor, 33_500);
  assert.equal(pricing.customerEstimatedGrossMarginMinor, 2_897);
});

test("traveler details are paired with Duffel offer passenger IDs", () => {
  const payload = validateCheckoutPayload(validPayload({
    travelers: [
      {
        travelerType: "child", title: "Miss", firstName: "Young", lastName: "Traveler",
        gender: "Female", dateOfBirthISO: "2015-05-04", nationality: "ca",
      },
      {
        travelerType: "adult", title: "Mr", firstName: "Test", lastName: "Traveler",
        gender: "Male", dateOfBirthISO: "1987-07-24",
      },
    ],
  }));
  const passengers = buildDuffelPassengers(payload.travelers, payload.contact, [
    { id: "pas_adult", type: "adult" },
    { id: "pas_child", type: "child" },
  ]);
  assert.equal(passengers[0].id, "pas_child");
  assert.equal(passengers[0].nationality, "CA");
  assert.deepEqual(passengers[1], {
    id: "pas_adult",
    title: "mr",
    given_name: "Test",
    family_name: "Traveler",
    born_on: "1987-07-24",
    gender: "m",
    email: "test@example.com",
    phone_number: "+14165551234",
  });
  const datedOffer = { slices: [{ segments: [{ departing_at: "2026-09-01T10:00:00Z" }] }] };
  validateTravelerTypesForOffer(payload.travelers, datedOffer);
  assert.throws(
    () => validateTravelerTypesForOffer([{ ...payload.travelers[0], travelerType: "adult" }], datedOffer),
    (error) => error.code === "traveler_type_age_mismatch"
  );
});

test("international offers require complete passports valid through the trip", () => {
  const offer = { slices: [{ segments: [{
    departing_at: "2026-09-01T10:00:00Z", arriving_at: "2026-09-10T10:00:00Z",
    origin: { iata_country_code: "CA" }, destination: { iata_country_code: "US" },
  }] }] };
  const traveler = {
    nationality: "CA", passportNumber: "TEST123", passportCountry: "CA", passportExpiryISO: "2027-01-01",
  };
  validateInternationalTravelerDocuments([traveler], offer);
  assert.throws(
    () => validateInternationalTravelerDocuments([{ ...traveler, passportNumber: null }], offer),
    (error) => error.code === "international_documents_required"
  );
  assert.throws(
    () => validateInternationalTravelerDocuments([{ ...traveler, passportExpiryISO: "2026-09-09" }], offer),
    (error) => error.code === "passport_expired_for_trip"
  );
  validateInternationalTravelerDocuments([{}], {
    slices: [{ segments: [{ origin: { iata_country_code: "CA" }, destination: { iata_country_code: "CA" } }] }],
  });
  assert.throws(
    () => validateInternationalTravelerDocuments([traveler], {
      slices: [{ segments: [{ origin: { iata_country_code: "CA" }, destination: {} }] }],
    }),
    (error) => error.code === "missing_offer_geography" && error.status === 502
  );
});

test("confirmation includes the fields displayed by iOS", () => {
  const confirmation = buildConfirmation({
    id: "ord_123",
    booking_reference: "ABC123",
    owner: { name: "Duffel Airways" },
    passengers: [{ given_name: "Test", family_name: "Traveler" }],
    slices: [
      { segments: [{
        origin: { iata_code: "YYZ", name: "Toronto Pearson" },
        destination: { iata_code: "JFK", name: "John F Kennedy" },
        departing_at: "2026-09-01T10:00:00Z",
        arriving_at: "2026-09-01T11:30:00Z",
        marketing_carrier: { name: "Duffel Airways", iata_code: "ZZ" },
        marketing_carrier_flight_number: "123",
      }] },
      { segments: [{
        origin: { iata_code: "JFK", name: "John F Kennedy" },
        destination: { iata_code: "YYZ", name: "Toronto Pearson" },
        departing_at: "2026-09-08T15:00:00Z",
        arriving_at: "2026-09-08T16:30:00Z",
        marketing_carrier: { name: "Duffel Airways", iata_code: "ZZ" },
        marketing_carrier_flight_number: "456",
      }] },
    ],
  }, {
    id: "session-123",
    customer_currency: "USD",
    charge_total_minor: 12_500,
    customer_total_minor: 12_500,
    trip_type: "round_trip_single_offer",
  });

  assert.equal(confirmation.orderId, "ord_123");
  assert.equal(confirmation.bookingSessionId, "session-123");
  assert.equal(confirmation.tripType, "round_trip_single_offer");
  assert.deepEqual(confirmation.bookingReferences, ["ABC123"]);
  assert.equal(confirmation.itinerary[0].title, "Outbound");
  assert.equal(confirmation.itinerary[0].origin, "YYZ");
  assert.deepEqual(confirmation.itinerary[0].airlines, ["Duffel Airways", "ZZ"]);
  assert.deepEqual(confirmation.itinerary[0].flightNumbers, ["ZZ123"]);
  assert.equal(confirmation.itinerary[1].title, "Return");
  assert.deepEqual(confirmation.travelers, ["Test Traveler"]);
});

test("only definite Duffel order failures are eligible for automatic refund", () => {
  for (const status of [400, 401, 402, 403, 404, 405, 413, 415, 422]) {
    assert.equal(isDefinitiveDuffelOrderFailureStatus(status), true);
  }
  for (const status of [408, 409, 425, 429]) {
    assert.equal(isDefinitiveDuffelOrderFailureStatus(status), false);
  }
  for (let status = 500; status <= 599; status += 1) {
    assert.equal(isDefinitiveDuffelOrderFailureStatus(status), false);
  }
  assert.equal(isDefinitiveDuffelOrderFailureStatus(201), false);
  assert.equal(isDefinitiveDuffelOrderFailureStatus(500), false);
  assert.equal(isDefinitiveDuffelOrderFailureStatus(504), false);
});

test("stale booking claims retry only before the durable Duffel POST marker", () => {
  const now = Date.parse("2026-08-08T12:10:00Z");
  const base = { booking_status: "booking_in_progress", updated_at: "2026-08-08T12:00:00Z" };
  assert.equal(staleBookingClaimDisposition(base, now, 300_000), "safe_retry");
  assert.equal(staleBookingClaimDisposition({ ...base, duffel_post_started_at: "2026-08-08T12:00:01Z" }, now, 300_000), "outcome_unknown");
  assert.equal(staleBookingClaimDisposition({ ...base, updated_at: "2026-08-08T12:09:00Z" }, now, 300_000), "active");
});

test("mocked quote, CAS races, uncertain orders, and confirmation preserve durable state", async () => {
  const sessions = new Map();
  let failNextRefundOutcomeUpdate = false;
  const fakePool = {
    async connect() {
      return { query: fakeQuery, release() {} };
    },
    query: fakeQuery,
  };

  async function fakeQuery(sql, params = []) {
    const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
    if (["begin", "commit", "rollback"].includes(normalized) || normalized.startsWith("select pg_advisory")) return { rows: [] };
    if (normalized.includes("where user_id = $1 and checkout_fingerprint = $2")) return { rows: [] };
    if (normalized.startsWith("insert into flight_booking_sessions")) {
      const row = {
        id: params[0], user_id: params[1], checkout_fingerprint: params[2], duffel_offer_id: params[3],
        offer_snapshot: JSON.parse(params[4]), payload_snapshot: JSON.parse(params[5]), traveler_info: JSON.parse(params[6]),
        contact_info: JSON.parse(params[7]), selected_services: JSON.parse(params[8]), currency: params[9],
        base_fare_minor: String(params[10]), taxes_minor: params[11] == null ? null : String(params[11]),
        offer_minor: String(params[12]), services_minor: String(params[13]), duffel_total_minor: String(params[14]),
        zippi_fee_minor: String(params[15]), charge_total_minor: String(params[16]),
        provider_currency: params[17], provider_offer_minor: String(params[18]), provider_services_minor: String(params[19]),
        provider_total_minor: String(params[20]), customer_currency: params[21], customer_fx_rate: String(params[22]),
        customer_fx_source: params[23], customer_fx_margin_bps: String(params[24]), customer_base_fare_minor: String(params[25]),
        customer_taxes_minor: params[26] == null ? null : String(params[26]), customer_services_minor: String(params[27]),
        customer_raw_converted_minor: String(params[28]), customer_fx_protection_minor: String(params[29]),
        customer_converted_minor: String(params[30]), customer_zippi_markup_bps: String(params[31]),
        customer_zippi_markup_minor: String(params[32]), customer_payment_processing_percent_bps: String(params[33]),
        customer_payment_processing_fixed_minor: String(params[34]), customer_payment_processing_cross_border_bps: String(params[35]),
        customer_payment_processing_effective_bps: String(params[36]), customer_payment_processing_allowance_minor: String(params[37]),
        customer_estimated_processing_minor: String(params[38]), customer_min_margin_target_minor: String(params[39]),
        customer_min_margin_top_up_minor: String(params[40]), customer_zippi_fee_minor: String(params[41]),
        customer_pre_round_minor: String(params[42]), customer_rounding_increment_minor: String(params[43]),
        customer_rounding_adjustment_minor: String(params[44]), customer_estimated_gross_margin_minor: String(params[45]),
        customer_total_minor: String(params[46]), trip_type: params[50],
        stripe_payment_status: "not_created",
        booking_status: "payment_setup", confirmation_snapshot: null, duffel_post_started_at: null,
        updated_at: new Date().toISOString(),
      };
      sessions.set(row.id, row);
      return { rows: [row] };
    }
    if (normalized.includes("set stripe_payment_intent_id = $2")) {
      const row = sessions.get(params[0]);
      if (!row || row.user_id !== params[3] || !["payment_setup", "awaiting_payment"].includes(row.booking_status)) return { rows: [] };
      Object.assign(row, { stripe_payment_intent_id: params[1], stripe_payment_status: params[2], booking_status: "awaiting_payment" });
      return { rows: [row] };
    }
    if (normalized.startsWith("select * from flight_booking_sessions where id = $1 and user_id = $2")) {
      const row = sessions.get(params[0]);
      return { rows: row && row.user_id === params[1] ? [row] : [] };
    }
    if (normalized === "select * from flight_booking_sessions where id = $1") {
      const row = sessions.get(params[0]);
      return { rows: row ? [row] : [] };
    }
    if (normalized.includes("set booking_status = 'booking_in_progress'")) {
      const row = sessions.get(params[0]);
      if (!["awaiting_payment", "payment_paid"].includes(row.booking_status)) return { rows: [] };
      Object.assign(row, {
        booking_status: "booking_in_progress",
        booking_claim_token: params[2],
        booking_claim_expires_at: new Date(Date.now() + Number(params[3])).toISOString(),
        recovery_status: null,
        failure_code: null,
        failure_message: null,
        updated_at: new Date().toISOString(),
      });
      // PostgreSQL returns a detached row snapshot; keep the claimed token stable
      // even if another writer replaces the durable token later.
      return { rows: [{ ...row }] };
    }
    if (normalized.includes("set booking_status = 'payment_canceled'")) {
      const row = sessions.get(params[0]);
      if (!row || row.user_id !== params[1] || !["payment_setup", "awaiting_payment"].includes(row.booking_status)) return { rows: [] };
      Object.assign(row, { booking_status: "payment_canceled", stripe_payment_status: params[2] });
      return { rows: [row] };
    }
    if (normalized.includes("set duffel_post_started_at = now()")) {
      const row = sessions.get(params[0]);
      if (!row || row.user_id !== params[1] || row.booking_claim_token !== params[2]
          || row.booking_status !== "booking_in_progress" || row.duffel_post_started_at) return { rows: [] };
      row.duffel_post_started_at = new Date().toISOString();
      return { rows: [row] };
    }
    if (normalized.includes("set booking_status = 'payment_paid', recovery_status = 'safe_retry_ready'")) {
      const row = sessions.get(params[0]);
      const stale = row && Date.now() - Date.parse(row.updated_at) > Number(params[1]);
      if (!row || !stale || row.booking_status !== "booking_in_progress" || row.duffel_post_started_at) return { rows: [] };
      Object.assign(row, {
        booking_status: "payment_paid", recovery_status: "safe_retry_ready",
        booking_claim_token: null, booking_claim_expires_at: null,
      });
      return { rows: [row] };
    }
    if (normalized.includes("set booking_status = 'booking_unknown', recovery_status = 'manual_reconciliation_required'")) {
      const row = sessions.get(params[0]);
      const stale = row && Date.now() - Date.parse(row.updated_at) > Number(params[1]);
      if (!row || !stale || row.booking_status !== "booking_in_progress" || !row.duffel_post_started_at) return { rows: [] };
      Object.assign(row, {
        booking_status: "booking_unknown", recovery_status: "manual_reconciliation_required",
        booking_claim_token: null, booking_claim_expires_at: null,
      });
      return { rows: [row] };
    }
    if (normalized.includes("recovery_status = 'refund_started'")) {
      const row = sessions.get(params[0]);
      if (!row || row.booking_status !== "booking_in_progress" || row.booking_claim_token !== params[4]) return { rows: [] };
      Object.assign(row, {
        booking_status: "booking_failed_refund_pending",
        failure_code: params[1],
        failure_message: params[2],
        recovery_status: "refund_started",
        duffel_request_id: params[3] || row.duffel_request_id,
      });
      return { rows: [row] };
    }
    if (normalized.includes("set stripe_payment_status = $2")) {
      sessions.get(params[0]).stripe_payment_status = params[1];
      return { rows: [] };
    }
    if (normalized.includes("set stripe_payment_status = $3, booking_status = $4")) {
      const row = sessions.get(params[0]);
      if (!row || row.user_id !== params[1] || !["payment_setup", "awaiting_payment", "payment_paid"].includes(row.booking_status)) return { rows: [] };
      Object.assign(row, { stripe_payment_status: params[2], booking_status: params[3] });
      return { rows: [row] };
    }
    if (normalized.startsWith("update flight_booking_sessions set stripe_payment_status = $3")) {
      const row = sessions.get(params[0]);
      if (!row || row.booking_claim_token !== params[1] || row.booking_status !== "booking_in_progress") return { rows: [] };
      row.stripe_payment_status = params[2];
      return { rows: [row] };
    }
    if (normalized.includes("set booking_status = 'confirmed'")) {
      const row = sessions.get(params[0]);
      if (!row || row.booking_status !== "booking_in_progress" || !row.duffel_post_started_at
          || row.booking_claim_token !== params[5]) return { rows: [] };
      Object.assign(row, {
        booking_status: "confirmed",
        stripe_payment_status: "succeeded",
        duffel_order_id: params[1],
        duffel_booking_reference: params[2],
        confirmation_snapshot: JSON.parse(params[4]),
        recovery_status: null,
        failure_code: null,
        failure_message: null,
        booking_claim_token: null,
        booking_claim_expires_at: null,
      });
      return { rows: [row] };
    }
    if (normalized.startsWith("update flight_booking_sessions set booking_status = $3")) {
      if (failNextRefundOutcomeUpdate) {
        failNextRefundOutcomeUpdate = false;
        throw new Error("simulated database failure after Stripe refund");
      }
      const row = sessions.get(params[0]);
      if (!row || row.booking_claim_token !== params[1] || !params[9].includes(row.booking_status)) return { rows: [] };
      Object.assign(row, {
        booking_status: params[2], failure_code: params[3], failure_message: params[4],
        recovery_status: params[5] || row.recovery_status,
        stripe_refund_id: params[6] || row.stripe_refund_id,
        duffel_request_id: params[7] || row.duffel_request_id,
      });
      if (params[8]) {
        row.booking_claim_token = null;
        row.booking_claim_expires_at = null;
      }
      return { rows: [row] };
    }
    throw new Error(`Unhandled fake SQL: ${normalized}`);
  }

  const offer = {
    id: "off_test",
    expires_at: "2099-01-01T00:00:00Z",
    total_amount: "120.00",
    total_currency: "USD",
    base_amount: "100.00",
    tax_amount: "20.00",
    slices: [
      { id: "slice_outbound", segments: [{
        departing_at: "2099-02-01T10:00:00Z",
        origin: { iata_country_code: "CA" }, destination: { iata_country_code: "CA" },
      }] },
      { id: "slice_return", segments: [{
        departing_at: "2099-02-08T10:00:00Z",
        origin: { iata_country_code: "CA" }, destination: { iata_country_code: "CA" },
      }] },
    ],
    passengers: [{ id: "pas_123", type: "adult" }],
    available_services: [],
    owner: { name: "Duffel Airways" },
  };
  let orderCreateCount = 0;
  let submittedOrderPayload = null;
  let orderMode = "success";
  let orderResponseHook = null;
  const fakeFetch = async (url, options = {}) => {
    if (options.method === "POST") {
      orderCreateCount += 1;
      submittedOrderPayload = JSON.parse(options.body);
      if (orderResponseHook) orderResponseHook();
      if (orderMode === "transport") throw new Error("socket closed");
      if (orderMode === "status_503") return fakeResponse(503, {
        errors: [{ code: "service_unavailable", message: "Order status unavailable" }],
        meta: { request_id: "duffel_request_503" },
      });
      if (orderMode === "status_422") return fakeResponse(422, {
        errors: [{ code: "offer_no_longer_available", message: "Offer unavailable" }],
        meta: { request_id: "duffel_request_422" },
      });
      return fakeResponse(201, {
        data: {
          id: "ord_123",
          live_mode: false,
          booking_reference: "ABC123",
          owner: { name: "Duffel Airways" },
          passengers: [{ given_name: "Test", family_name: "Traveler" }],
          slices: [
            { segments: [{
              origin: { iata_code: "YYZ", name: "Toronto Pearson" },
              destination: { iata_code: "JFK", name: "John F Kennedy" },
              departing_at: "2099-02-01T10:00:00Z",
              arriving_at: "2099-02-01T12:00:00Z",
              marketing_carrier: { name: "Duffel Airways", iata_code: "ZZ" },
              marketing_carrier_flight_number: "123",
            }] },
            { segments: [{
              origin: { iata_code: "JFK", name: "John F Kennedy" },
              destination: { iata_code: "YYZ", name: "Toronto Pearson" },
              departing_at: "2099-02-08T14:00:00Z",
              arriving_at: "2099-02-08T16:00:00Z",
              marketing_carrier: { name: "Duffel Airways", iata_code: "ZZ" },
              marketing_carrier_flight_number: "456",
            }] },
          ],
        },
        meta: { request_id: "duffel_request_1" },
      });
    }
    assert.match(url, /\/air\/offers\/off_test/);
    return fakeResponse(200, { data: offer });
  };
  function fakeResponse(status, body) {
    return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) };
  }

  let paymentStatus = "requires_payment_method";
  let paymentCreateCount = 0;
  let retrieveHook = null;
  let refundCreateCount = 0;
  let refundMode = "throw";
  const fakeStripe = {
    paymentIntents: {
      create: async () => {
        paymentCreateCount += 1;
        return { id: `pi_test_${paymentCreateCount}`, client_secret: `pi_test_${paymentCreateCount}_secret`, amount: 12_500, currency: "usd", status: "requires_payment_method" };
      },
      retrieve: async () => {
        if (retrieveHook) retrieveHook();
        return { id: "pi_test", client_secret: "pi_test_secret", amount: 12_500, currency: "usd", status: paymentStatus };
      },
    },
    refunds: { create: async () => {
      refundCreateCount += 1;
      if (refundMode === "throw") throw new Error("refund must not run");
      return { id: `re_test_${refundCreateCount}`, status: refundMode };
    } },
  };

  let uuidCounter = 0;

  const service = createFlightBookingService({
    dbPool: fakePool,
    stripe: fakeStripe,
    duffelToken: "duffel_test_fake",
    duffelMode: "TEST",
    duffelVersion: "v2",
    fetchWithTimeout: fakeFetch,
    randomUUID: () => {
      uuidCounter += 1;
      return `11111111-1111-4111-8111-${String(uuidCounter).padStart(12, "0")}`;
    },
    enabled: true,
    getExchangeRates: async () => ({ base: "USD", rates: { USD: 1, CAD: 1.35 }, source: "test" }),
    pricingConfig: pricingConfig(),
  });

  const quote = await service.quoteCheckout(validPayload({ returnOfferId: "off_test" }));
  assert.equal(quote.tripType, "round_trip_single_offer");
  assert.equal(quote.quote.totalMinor, 12_500);
  assert.equal(paymentCreateCount, 0);
  assert.equal(sessions.size, 0);

  const setupPayload = validPayload({ returnOfferId: "off_test" });
  const setup = await service.paymentSetup("user_1", setupPayload);
  assert.equal(setup.paymentIntentClientSecret, "pi_test_1_secret");
  assert.equal(setup.quote.lineItems.baseFareMinor, 10_000);
  assert.equal(setup.quote.lineItems.taxesMinor, 2_000);
  assert.equal(setup.quote.lineItems.zippiFeeMinor, 499);
  assert.equal(setup.quote.lineItems.preRoundMinor, 12_499);
  assert.equal(setup.quote.lineItems.roundingAdjustmentMinor, 1);
  assert.equal(paymentCreateCount, 1);
  assert.equal(sessions.get(setup.bookingSessionId).trip_type, "round_trip_single_offer");

  const canceledSetup = await service.paymentSetup("user_canceled", setupPayload);
  paymentStatus = "canceled";
  const restartedSetup = await service.paymentSetup("user_canceled", { ...setupPayload, bookingSessionId: canceledSetup.bookingSessionId });
  assert.notEqual(restartedSetup.bookingSessionId, canceledSetup.bookingSessionId);
  assert.equal(sessions.get(canceledSetup.bookingSessionId).booking_status, "payment_canceled");
  assert.equal(paymentCreateCount, 3, "canceled intent creates exactly one replacement intent on a fresh session");
  paymentStatus = "requires_payment_method";

  retrieveHook = () => { sessions.get(setup.bookingSessionId).booking_status = "confirmed"; };
  await assert.rejects(
    service.paymentSetup("user_1", { ...setupPayload, bookingSessionId: setup.bookingSessionId }),
    (error) => error.code === "booking_session_advanced"
  );
  assert.equal(sessions.get(setup.bookingSessionId).booking_status, "confirmed");

  sessions.get(setup.bookingSessionId).booking_status = "awaiting_payment";
  retrieveHook = () => { sessions.get(setup.bookingSessionId).booking_status = "booking_in_progress"; };
  const racingStatus = await service.getBookingStatus("user_1", setup.bookingSessionId);
  assert.equal(racingStatus.status, "booking_in_progress");

  sessions.get(setup.bookingSessionId).booking_status = "awaiting_payment";
  retrieveHook = null;
  paymentStatus = "succeeded";

  const stalePreSetup = await service.paymentSetup("user_stale_pre", setupPayload);
  Object.assign(sessions.get(stalePreSetup.bookingSessionId), {
    booking_status: "booking_in_progress", updated_at: "2000-01-01T00:00:00Z", duffel_post_started_at: null,
  });
  const stalePreStatus = await service.getBookingStatus("user_stale_pre", stalePreSetup.bookingSessionId);
  assert.equal(stalePreStatus.status, "payment_paid");
  assert.equal(stalePreStatus.recoveryStatus, "safe_retry_ready");
  const stalePreConfirmation = await service.confirmBooking("user_stale_pre", stalePreSetup.bookingSessionId);
  assert.equal(stalePreConfirmation.orderId, "ord_123");
  assert.equal(sessions.get(stalePreSetup.bookingSessionId).recovery_status, null);
  assert.equal(sessions.get(stalePreSetup.bookingSessionId).failure_code, null);

  const stalePostSetup = await service.paymentSetup("user_stale_post", setupPayload);
  Object.assign(sessions.get(stalePostSetup.bookingSessionId), {
    booking_status: "booking_in_progress", updated_at: "2000-01-01T00:00:00Z", duffel_post_started_at: "2000-01-01T00:00:01Z",
  });
  const stalePostStatus = await service.getBookingStatus("user_stale_post", stalePostSetup.bookingSessionId);
  assert.equal(stalePostStatus.status, "booking_unknown");
  assert.equal(stalePostStatus.recoveryStatus, "manual_reconciliation_required");

  orderMode = "status_503";
  const unavailableSetup = await service.paymentSetup("user_503", setupPayload);
  await assert.rejects(
    service.confirmBooking("user_503", unavailableSetup.bookingSessionId),
    (error) => error.code === "booking_outcome_unknown"
  );
  assert.equal(sessions.get(unavailableSetup.bookingSessionId).booking_status, "booking_unknown");

  orderMode = "transport";
  const transportSetup = await service.paymentSetup("user_transport", setupPayload);
  await assert.rejects(
    service.confirmBooking("user_transport", transportSetup.bookingSessionId),
    (error) => error.code === "booking_outcome_unknown"
  );
  assert.equal(sessions.get(transportSetup.bookingSessionId).booking_status, "booking_unknown");
  assert.equal(refundCreateCount, 0);

  orderMode = "status_422";
  refundMode = "pending";
  const refundSetup = await service.paymentSetup("user_refund", setupPayload);
  await assert.rejects(
    service.confirmBooking("user_refund", refundSetup.bookingSessionId),
    (error) => error.code === "refund_pending"
  );
  assert.equal(sessions.get(refundSetup.bookingSessionId).booking_status, "booking_failed_refund_pending");
  assert.equal(sessions.get(refundSetup.bookingSessionId).recovery_status, "refund_pending");

  refundMode = "succeeded";
  const refundCrashSetup = await service.paymentSetup("user_refund_crash", setupPayload);
  failNextRefundOutcomeUpdate = true;
  await assert.rejects(
    service.confirmBooking("user_refund_crash", refundCrashSetup.bookingSessionId),
    (error) => error.code === "refund_pending"
  );
  assert.equal(sessions.get(refundCrashSetup.bookingSessionId).booking_status, "booking_failed_refund_pending");
  assert.equal(sessions.get(refundCrashSetup.bookingSessionId).recovery_status, "refund_started");
  const refundCrashStatus = await service.getBookingStatus("user_refund_crash", refundCrashSetup.bookingSessionId);
  assert.equal(refundCrashStatus.status, "booking_failed_refund_pending");
  assert.equal(refundCrashStatus.recoveryStatus, "refund_started");
  const orderCountAfterRefundCrash = orderCreateCount;
  await assert.rejects(
    service.confirmBooking("user_refund_crash", refundCrashSetup.bookingSessionId),
    (error) => error.code === "refund_pending"
  );
  assert.equal(orderCreateCount, orderCountAfterRefundCrash, "a refunded session must never retry the Duffel order");
  refundMode = "throw";

  orderMode = "success";
  const staleWriterSetup = await service.paymentSetup("user_stale_writer", setupPayload);
  const replacementToken = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  orderResponseHook = () => {
    sessions.get(staleWriterSetup.bookingSessionId).booking_claim_token = replacementToken;
    orderResponseHook = null;
  };
  await assert.rejects(
    service.confirmBooking("user_stale_writer", staleWriterSetup.bookingSessionId),
    (error) => error.code === "booking_outcome_unknown"
  );
  const staleWriter = sessions.get(staleWriterSetup.bookingSessionId);
  assert.equal(staleWriter.booking_claim_token, replacementToken);
  assert.equal(staleWriter.booking_status, "booking_in_progress");
  assert.ok(staleWriter.duffel_post_started_at, "the stale writer had already crossed the durable Duffel POST marker");

  orderMode = "success";
  const paidStatus = await service.getBookingStatus("user_1", setup.bookingSessionId);
  assert.equal(paidStatus.status, "payment_paid");
  assert.equal(paidStatus.confirmation, null);
  await assert.rejects(
    service.getBookingStatus("another_user", setup.bookingSessionId),
    (error) => error.code === "booking_session_not_found"
  );
  const firstConfirmation = await service.confirmBooking("user_1", setup.bookingSessionId);
  const repeatedConfirmation = await service.confirmBooking("user_1", setup.bookingSessionId);
  const confirmedStatus = await service.getBookingStatus("user_1", setup.bookingSessionId);

  assert.equal(firstConfirmation.orderId, "ord_123");
  assert.equal(firstConfirmation.tripType, "round_trip_single_offer");
  assert.equal(firstConfirmation.itinerary.length, 2);
  assert.deepEqual(repeatedConfirmation, firstConfirmation);
  assert.equal(orderCreateCount, 7, "one stale-claim retry, one 503, one transport failure, two definitive failures, one fenced stale writer, and one final successful order attempt");
  assert.deepEqual(submittedOrderPayload.data.selected_offers, ["off_test"]);
  assert.equal(confirmedStatus.status, "confirmed");
  assert.equal(confirmedStatus.confirmation.orderId, "ord_123");
  assert.equal(sessions.get(setup.bookingSessionId).booking_status, "confirmed");
});

test("status read reconstructs a protected two-sided session without repricing drift", async () => {
  const sessions = new Map();
  const fakePool = {
    async connect() {
      return { query: fakeQuery, release() {} };
    },
    query: fakeQuery,
  };

  async function fakeQuery(sql, params = []) {
    const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
    if (["begin", "commit", "rollback"].includes(normalized) || normalized.startsWith("select pg_advisory")) return { rows: [] };
    if (normalized.includes("where user_id = $1 and checkout_fingerprint = $2")) return { rows: [] };
    if (normalized.startsWith("insert into flight_booking_sessions")) {
      const row = {
        id: params[0], user_id: params[1], checkout_fingerprint: params[2], duffel_offer_id: params[3],
        offer_snapshot: JSON.parse(params[4]), payload_snapshot: JSON.parse(params[5]), traveler_info: JSON.parse(params[6]),
        contact_info: JSON.parse(params[7]), selected_services: JSON.parse(params[8]), currency: params[9],
        base_fare_minor: String(params[10]), taxes_minor: params[11] == null ? null : String(params[11]),
        offer_minor: String(params[12]), services_minor: String(params[13]), duffel_total_minor: String(params[14]),
        zippi_fee_minor: String(params[15]), charge_total_minor: String(params[16]),
        provider_currency: params[17], provider_offer_minor: String(params[18]), provider_services_minor: String(params[19]),
        provider_total_minor: String(params[20]), customer_currency: params[21], customer_fx_rate: String(params[22]),
        customer_fx_source: params[23], customer_fx_margin_bps: String(params[24]), customer_base_fare_minor: String(params[25]),
        customer_taxes_minor: params[26] == null ? null : String(params[26]), customer_services_minor: String(params[27]),
        customer_raw_converted_minor: String(params[28]), customer_fx_protection_minor: String(params[29]),
        customer_converted_minor: String(params[30]), customer_zippi_markup_bps: String(params[31]),
        customer_zippi_markup_minor: String(params[32]), customer_payment_processing_percent_bps: String(params[33]),
        customer_payment_processing_fixed_minor: String(params[34]), customer_payment_processing_cross_border_bps: String(params[35]),
        customer_payment_processing_effective_bps: String(params[36]), customer_payment_processing_allowance_minor: String(params[37]),
        customer_estimated_processing_minor: String(params[38]), customer_min_margin_target_minor: String(params[39]),
        customer_min_margin_top_up_minor: String(params[40]), customer_zippi_fee_minor: String(params[41]),
        customer_pre_round_minor: String(params[42]), customer_rounding_increment_minor: String(params[43]),
        customer_rounding_adjustment_minor: String(params[44]), customer_estimated_gross_margin_minor: String(params[45]),
        customer_total_minor: String(params[46]), trip_type: params[50],
        stripe_payment_status: "not_created",
        booking_status: "payment_setup",
        confirmation_snapshot: null,
        updated_at: new Date().toISOString(),
      };
      sessions.set(row.id, row);
      return { rows: [row] };
    }
    if (normalized.includes("set stripe_payment_intent_id = $2")) {
      const row = sessions.get(params[0]);
      Object.assign(row, { stripe_payment_intent_id: params[1], stripe_payment_status: params[2], booking_status: "awaiting_payment" });
      return { rows: [row] };
    }
    if (normalized.startsWith("select * from flight_booking_sessions where id = $1 and user_id = $2")) {
      const row = sessions.get(params[0]);
      return { rows: row && row.user_id === params[1] ? [row] : [] };
    }
    if (normalized.includes("set stripe_payment_status = $3, booking_status = $4")) {
      const row = sessions.get(params[0]);
      Object.assign(row, { stripe_payment_status: params[2], booking_status: params[3] });
      return { rows: [row] };
    }
    throw new Error(`Unhandled fake SQL: ${normalized}`);
  }

  const offer = {
    id: "off_cad_test",
    expires_at: "2099-01-01T00:00:00Z",
    total_amount: "89.63",
    total_currency: "USD",
    base_amount: "75.96",
    tax_amount: "13.67",
    slices: [{ id: "slice_outbound", segments: [{
      departing_at: "2099-02-01T10:00:00Z",
      origin: { iata_country_code: "US" }, destination: { iata_country_code: "US" },
    }] }],
    passengers: [{ id: "pas_123", type: "adult" }],
    available_services: [],
    owner: { name: "Duffel Airways" },
  };

  let createdIntent = null;
  const fakeStripe = {
    paymentIntents: {
      create: async (payload) => {
        createdIntent = { ...payload };
        return {
          id: "pi_cad_test",
          client_secret: "pi_cad_test_secret",
          amount: payload.amount,
          currency: payload.currency,
          status: "requires_payment_method",
        };
      },
      retrieve: async () => ({
        id: "pi_cad_test",
        client_secret: "pi_cad_test_secret",
        amount: createdIntent.amount,
        currency: createdIntent.currency,
        status: "requires_payment_method",
      }),
    },
    refunds: { create: async () => { throw new Error("refund not expected"); } },
  };

  const service = createFlightBookingService({
    dbPool: fakePool,
    stripe: fakeStripe,
    duffelToken: "duffel_test_fake",
    duffelMode: "TEST",
    duffelVersion: "v2",
    fetchWithTimeout: async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ data: offer }) }),
    randomUUID: () => "22222222-2222-4222-8222-000000000001",
    enabled: true,
    getExchangeRates: async () => ({ base: "USD", rates: { USD: 1, CAD: 1.395557 }, source: "test" }),
    pricingConfig: {
      zippiFeeMinor: 499,
      fxMarginBps: 500,
      zippiMarkupBps: 700,
      minGrossMarginMinor: 1599,
      paymentProcessingPercentBps: 350,
      paymentProcessingFixedMinor: 30,
      paymentProcessingCrossBorderBps: 0,
    },
  });

  const quote = await service.quoteCheckout({ offerId: "off_cad_test", currency: "CAD" });
  const setup = await service.paymentSetup("user_cad", {
    offerId: "off_cad_test",
    currency: "CAD",
    totalMinor: quote.quote.totalMinor,
    baggageServiceIds: [],
    travelers: [{
      travelerType: "adult",
      title: "Mr",
      firstName: "Smoke",
      middleName: null,
      lastName: "Tester",
      gender: "Male",
      dateOfBirthISO: "1987-07-24",
    }],
    contact: { email: "smoke@example.com", phone: "+14165551234" },
  });
  const status = await service.getBookingStatus("user_cad", setup.bookingSessionId);

  assert.equal(setup.quote.totalMinor, 15_500);
  assert.equal(status.status, "awaiting_payment");
  assert.equal(status.paymentStatus, "requires_payment_method");
  assert.equal(status.quote.currency, "CAD");
  assert.equal(status.quote.totalMinor, setup.quote.totalMinor);
  assert.equal(status.quote.customer.lineItems.rawConvertedMinor, setup.quote.customer.lineItems.rawConvertedMinor);
  assert.equal(status.quote.customer.lineItems.fxProtectionMinor, setup.quote.customer.lineItems.fxProtectionMinor);
  assert.equal(status.quote.customer.lineItems.zippiMarkupMinor, setup.quote.customer.lineItems.zippiMarkupMinor);
  assert.equal(status.quote.customer.lineItems.paymentProcessingAllowanceMinor, setup.quote.customer.lineItems.paymentProcessingAllowanceMinor);
  assert.equal(status.quote.customer.lineItems.minMarginTopUpMinor, setup.quote.customer.lineItems.minMarginTopUpMinor);
  assert.equal(status.quote.customer.lineItems.estimatedGrossMarginMinor, setup.quote.customer.lineItems.estimatedGrossMarginMinor);
  assert.equal(status.quote.provider.currency, "USD");
  assert.equal(status.quote.provider.totalMinor, 8_963);
  assert.equal(status.tripType, "one_way");
});

test("status read keeps legacy sessions readable", async () => {
  const legacySession = {
    id: "33333333-3333-4333-8333-000000000001",
    user_id: "legacy_user",
    booking_status: "confirmed",
    stripe_payment_status: "succeeded",
    confirmation_snapshot: { orderId: "ord_legacy" },
    updated_at: "2026-08-09T00:00:00.000Z",
    currency: "USD",
    base_fare_minor: "10000",
    taxes_minor: "2000",
    offer_minor: "12000",
    services_minor: "0",
    duffel_total_minor: "12000",
    zippi_fee_minor: "499",
    charge_total_minor: "12500",
    offer_snapshot: { baseAmount: "100.00", taxAmount: "20.00" },
  };
  const fakePool = {
    query: async (sql, params = []) => {
      const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
      if (normalized.startsWith("select * from flight_booking_sessions where id = $1 and user_id = $2")) {
        return { rows: params[0] === legacySession.id && params[1] === legacySession.user_id ? [legacySession] : [] };
      }
      throw new Error(`Unhandled fake SQL: ${normalized}`);
    },
  };
  const service = createFlightBookingService({
    dbPool: fakePool,
    stripe: { paymentIntents: { retrieve: async () => { throw new Error("not expected"); } } },
    duffelToken: "duffel_test_fake",
    duffelMode: "TEST",
    duffelVersion: "v2",
    fetchWithTimeout: async () => { throw new Error("not expected"); },
    randomUUID: () => legacySession.id,
    enabled: true,
  });

  const status = await service.getBookingStatus("legacy_user", legacySession.id);
  assert.equal(status.status, "confirmed");
  assert.equal(status.paymentStatus, "succeeded");
  assert.equal(status.quote.currency, "USD");
  assert.equal(status.quote.provider.currency, "USD");
  assert.equal(status.quote.totalMinor, 12_500);
  assert.equal(status.quote.customer.lineItems.rawConvertedMinor, 12_000);
  assert.deepEqual(status.confirmation, { orderId: "ord_legacy" });
});
