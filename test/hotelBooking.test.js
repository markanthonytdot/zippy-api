const test = require("node:test");
const assert = require("node:assert/strict");
const {
  HotelBookingError,
  normalizeQuote,
  publicQuote,
  validateGuestPayload,
  createHotelBookingService,
} = require("../lib/hotelBooking");

test("Hotel quote converts provider total without Flight markup or fees", () => {
  const quote = {
    id: "quo_test",
    total_amount: "100.00",
    total_currency: "USD",
    check_in_date: "2026-10-10",
    check_out_date: "2026-10-13",
    rooms: 1,
  };
  const pricing = normalizeQuote(quote, "CAD", {
    base: "USD",
    rates: { USD: 1, CAD: 1.35 },
    source: "test_rates",
  });
  assert.equal(pricing.providerTotalMinor, 10_000);
  assert.equal(pricing.customerTotalMinor, 13_500);
  assert.equal(pricing.fxRate, 1.35);
  const output = publicQuote(quote, pricing);
  assert.deepEqual(output.provider, { currency: "USD", totalMinor: 10_000 });
  assert.equal(output.currency, "CAD");
  assert.equal(output.totalMinor, 13_500);
});

test("Hotel quote uses exact provider minor units when customer currency matches", () => {
  const pricing = normalizeQuote({ id: "quo_test", total_amount: "839.95", total_currency: "USD" }, "USD", {
    base: "USD", rates: { USD: 1 }, source: "same",
  });
  assert.equal(pricing.providerTotalMinor, 83_995);
  assert.equal(pricing.customerTotalMinor, 83_995);
});

test("Hotel guests require real names, birth dates, verified contact shapes", () => {
  const value = validateGuestPayload({
    guests: [{ firstName: "Amelia", lastName: "Earhart", dateOfBirthISO: "1987-07-24" }],
    contact: { email: "amelia@example.com", phone: "+14165551234" },
  });
  assert.equal(value.guests[0].firstName, "Amelia");
  assert.equal(value.contact.phone, "+14165551234");
  assert.throws(
    () => validateGuestPayload({ guests: [{ firstName: "A", lastName: "B" }], contact: { email: "bad", phone: "416" } }),
    (error) => error instanceof HotelBookingError && error.code === "invalid_guest_birth_date"
  );
});

function paidSession() {
  return {
    id: "11111111-1111-4111-8111-111111111111", user_id: "usr_test", booking_status: "payment_paid",
    stripe_payment_intent_id: "pi_test", stripe_payment_status: "succeeded", customer_currency: "CAD",
    customer_total_minor: 13_500, provider_currency: "USD", provider_total_minor: 10_000,
    duffel_quote_id: "quo_test", duffel_rate_id: "rat_test", duffel_post_started_at: null,
    hotel_snapshot: { id: "acc_test", name: "Test Hotel" }, room_snapshot: { id: "rat_test", title: "King Room" },
    search_snapshot: { destination: "Toronto", checkIn: "2026-10-10", checkOut: "2026-10-13", adults: 1, rooms: 1 },
    guest_info: [{ firstName: "Test", lastName: "Traveler", dateOfBirthISO: "1987-07-24" }],
    contact_info: { email: "test@example.com", phone: "+14165551234" }, quote_snapshot: { id: "quo_test" },
  };
}

test("transient quote verification failure releases only the pre-POST claim", async () => {
  const session = paidSession();
  const dbPool = { async query(sql) {
    const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
    if (normalized.startsWith("update hotel_booking_sessions set booking_status='booking_in_progress'")) {
      session.booking_status = "booking_in_progress"; session.booking_claim_token = "claim"; return { rows: [{ ...session }] };
    }
    if (normalized.includes("failure_code='quote_verification_unavailable'")) {
      session.booking_status = "payment_paid"; session.booking_claim_token = null; return { rows: [{ ...session }] };
    }
    throw new Error(`unexpected SQL: ${normalized}`);
  } };
  const service = createHotelBookingService({
    dbPool, stripe: { paymentIntents: { retrieve: async () => ({ status: "succeeded", amount: 13_500, currency: "cad" }) } },
    duffelToken: "duffel_test_token", duffelMode: "TEST", duffelVersion: "v2", enabled: true,
    randomUUID: () => "22222222-2222-4222-8222-222222222222", fetchWithTimeout: async () => { throw new Error("temporary network failure"); },
  });
  await assert.rejects(() => service.confirm("usr_test", session.id), (error) => error.code === "quote_verification_unavailable");
  assert.equal(session.booking_status, "payment_paid");
  assert.equal(session.duffel_post_started_at, null);
});

test("ambiguous Duffel Stays POST is fenced unknown and never posted twice", async () => {
  const session = paidSession();
  let postCount = 0;
  const dbPool = { async query(sql) {
    const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
    if (normalized.startsWith("update hotel_booking_sessions set booking_status='booking_in_progress'")) {
      if (session.booking_status !== "payment_paid" || session.duffel_post_started_at) return { rows: [] };
      session.booking_status = "booking_in_progress"; session.booking_claim_token = "claim"; return { rows: [{ ...session }] };
    }
    if (normalized.startsWith("select * from hotel_booking_sessions")) return { rows: [{ ...session }] };
    if (normalized.includes("set duffel_post_started_at=now()")) {
      session.duffel_post_started_at = new Date().toISOString(); return { rows: [{ ...session }] };
    }
    if (normalized.includes("booking_status='booking_unknown'")) {
      session.booking_status = "booking_unknown"; session.recovery_status = "manual_reconciliation_required"; return { rows: [{ ...session }] };
    }
    throw new Error(`unexpected SQL: ${normalized}`);
  } };
  const fetchWithTimeout = async (url) => {
    if (url.endsWith("/stays/quotes/quo_test")) return {
      ok: true, status: 200, text: async () => JSON.stringify({ data: { id: "quo_test", total_amount: "100.00", total_currency: "USD" } }),
    };
    postCount += 1;
    throw new Error("connection reset after submit");
  };
  const service = createHotelBookingService({
    dbPool, stripe: { paymentIntents: { retrieve: async () => ({ status: "succeeded", amount: 13_500, currency: "cad" }) } },
    duffelToken: "duffel_test_token", duffelMode: "TEST", duffelVersion: "v2", enabled: true,
    randomUUID: () => "22222222-2222-4222-8222-222222222222", fetchWithTimeout,
  });
  await assert.rejects(() => service.confirm("usr_test", session.id), (error) => error.code === "booking_outcome_unknown");
  await assert.rejects(() => service.confirm("usr_test", session.id), (error) => error.code === "booking_outcome_unknown");
  assert.equal(postCount, 1);
  assert.equal(session.booking_status, "booking_unknown");
});
