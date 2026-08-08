const test = require("node:test");
const assert = require("node:assert/strict");
const {
  buildConfirmation,
  buildDuffelPassengers,
  calculatePricing,
  createFlightBookingService,
  decimalToMinor,
  isDefinitiveDuffelOrderFailureStatus,
  minorToDecimal,
  requestedServiceQuantities,
  resolveSelectedServices,
  validateCheckoutPayload,
} = require("../lib/flightBooking");

function validPayload(overrides = {}) {
  return {
    offerId: "off_test",
    returnOfferId: null,
    currency: "USD",
    totalMinor: 12_299,
    baggageServiceIds: [],
    travelers: [{
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

test("converts provider decimal prices without floating point arithmetic", () => {
  assert.equal(decimalToMinor("120.00", "USD"), 12_000);
  assert.equal(decimalToMinor("120", "JPY"), 120);
  assert.equal(decimalToMinor("1.234", "KWD"), 1_234);
  assert.equal(minorToDecimal(12_345, "USD"), "123.45");
});

test("checkout validation blocks round trips and non-E.164 phone numbers", () => {
  assert.throws(() => validateCheckoutPayload(validPayload({ returnOfferId: "off_return" })), /one-way/i);
  assert.throws(() => validateCheckoutPayload(validPayload({ contact: { email: "test@example.com", phone: "4165551234" } })), /international format/i);
  assert.throws(() => validateCheckoutPayload(validPayload({ bookingSessionId: "not-a-uuid" })), /session ID is invalid/i);
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
  const pricing = calculatePricing({ total_amount: "120.00", total_currency: "USD" }, services, 299);
  assert.deepEqual(services.map(({ id, quantity }) => ({ id, quantity })), [
    { id: "ase_bag", quantity: 2 },
    { id: "ase_seat", quantity: 1 },
  ]);
  assert.equal(pricing.duffelTotalMinor, 17_800);
  assert.equal(pricing.chargeTotalMinor, 18_099);
});

test("traveler details are paired with Duffel offer passenger IDs", () => {
  const payload = validateCheckoutPayload(validPayload());
  const passengers = buildDuffelPassengers(payload.travelers, payload.contact, [{ id: "pas_123" }]);
  assert.deepEqual(passengers[0], {
    id: "pas_123",
    title: "mr",
    given_name: "Test",
    family_name: "Traveler",
    born_on: "1987-07-24",
    gender: "m",
    email: "test@example.com",
    phone_number: "+14165551234",
  });
});

test("confirmation includes the fields displayed by iOS", () => {
  const confirmation = buildConfirmation({
    id: "ord_123",
    booking_reference: "ABC123",
    owner: { name: "Duffel Airways" },
    passengers: [{ given_name: "Test", family_name: "Traveler" }],
    slices: [{ segments: [{
      origin: { iata_code: "YYZ" },
      destination: { iata_code: "JFK" },
      departing_at: "2026-09-01T10:00:00Z",
      arriving_at: "2026-09-01T11:30:00Z",
      marketing_carrier_flight_number: "ZZ123",
    }] }],
  }, { id: "session-123", currency: "USD", charge_total_minor: 12_299 });

  assert.equal(confirmation.orderId, "ord_123");
  assert.equal(confirmation.bookingSessionId, "session-123");
  assert.equal(confirmation.itinerary[0].origin, "YYZ");
  assert.deepEqual(confirmation.travelers, ["Test Traveler"]);
});

test("only definite Duffel order failures are eligible for automatic refund", () => {
  assert.equal(isDefinitiveDuffelOrderFailureStatus(422), true);
  assert.equal(isDefinitiveDuffelOrderFailureStatus(503), true);
  assert.equal(isDefinitiveDuffelOrderFailureStatus(201), false);
  assert.equal(isDefinitiveDuffelOrderFailureStatus(500), false);
  assert.equal(isDefinitiveDuffelOrderFailureStatus(504), false);
});

test("mocked setup and confirmation complete once and return persisted confirmation", async () => {
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
        offer_minor: String(params[10]), services_minor: String(params[11]), duffel_total_minor: String(params[12]),
        zippi_fee_minor: String(params[13]), charge_total_minor: String(params[14]), stripe_payment_status: "not_created",
        booking_status: "payment_setup", confirmation_snapshot: null,
      };
      sessions.set(row.id, row);
      return { rows: [row] };
    }
    if (normalized.includes("set stripe_payment_intent_id = $2")) {
      const row = sessions.get(params[0]);
      Object.assign(row, { stripe_payment_intent_id: params[1], stripe_payment_status: params[2], booking_status: "awaiting_payment" });
      return { rows: [] };
    }
    if (normalized.startsWith("select * from flight_booking_sessions where id = $1 and user_id = $2")) {
      return { rows: sessions.has(params[0]) ? [sessions.get(params[0])] : [] };
    }
    if (normalized.includes("set booking_status = 'booking_in_progress'")) {
      const row = sessions.get(params[0]);
      if (!["awaiting_payment", "payment_paid"].includes(row.booking_status)) return { rows: [] };
      row.booking_status = "booking_in_progress";
      return { rows: [row] };
    }
    if (normalized.includes("set stripe_payment_status = $2")) {
      sessions.get(params[0]).stripe_payment_status = params[1];
      return { rows: [] };
    }
    if (normalized.includes("set booking_status = 'confirmed'")) {
      const row = sessions.get(params[0]);
      Object.assign(row, {
        booking_status: "confirmed",
        stripe_payment_status: "succeeded",
        duffel_order_id: params[1],
        duffel_booking_reference: params[2],
        confirmation_snapshot: JSON.parse(params[4]),
      });
      return { rows: [] };
    }
    throw new Error(`Unhandled fake SQL: ${normalized}`);
  }

  const offer = {
    id: "off_test",
    expires_at: "2099-01-01T00:00:00Z",
    total_amount: "120.00",
    total_currency: "USD",
    slices: [{ id: "slice_1" }],
    passengers: [{ id: "pas_123" }],
    available_services: [],
    owner: { name: "Duffel Airways" },
  };
  let orderCreateCount = 0;
  const fakeFetch = async (url, options = {}) => {
    if (options.method === "POST") {
      orderCreateCount += 1;
      return fakeResponse(201, {
        data: {
          id: "ord_123",
          booking_reference: "ABC123",
          owner: { name: "Duffel Airways" },
          passengers: [{ given_name: "Test", family_name: "Traveler" }],
          slices: [],
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
  const fakeStripe = {
    paymentIntents: {
      create: async () => ({ id: "pi_test", client_secret: "pi_test_secret", amount: 12_299, currency: "usd", status: paymentStatus }),
      retrieve: async () => ({ id: "pi_test", client_secret: "pi_test_secret", amount: 12_299, currency: "usd", status: paymentStatus }),
    },
    refunds: { create: async () => assert.fail("happy path must not refund") },
  };

  const service = createFlightBookingService({
    dbPool: fakePool,
    stripe: fakeStripe,
    duffelToken: "duffel_test_fake",
    duffelMode: "TEST",
    duffelVersion: "v2",
    fetchWithTimeout: fakeFetch,
    randomUUID: () => "11111111-1111-4111-8111-111111111111",
    enabled: true,
    zippiFeeMinor: 299,
  });

  const setup = await service.paymentSetup("user_1", validPayload());
  assert.equal(setup.paymentIntentClientSecret, "pi_test_secret");
  paymentStatus = "succeeded";
  const firstConfirmation = await service.confirmBooking("user_1", setup.bookingSessionId);
  const repeatedConfirmation = await service.confirmBooking("user_1", setup.bookingSessionId);

  assert.equal(firstConfirmation.orderId, "ord_123");
  assert.deepEqual(repeatedConfirmation, firstConfirmation);
  assert.equal(orderCreateCount, 1);
  assert.equal(sessions.get(setup.bookingSessionId).booking_status, "confirmed");
});
