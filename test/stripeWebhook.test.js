const test = require("node:test");
const assert = require("node:assert/strict");

const {
  createStripeWebhookHandler,
  normalizedStripeEvent,
  processStripeEvent,
} = require("../lib/stripeWebhook");

const SESSION_ID = "11111111-1111-4111-8111-111111111111";

test("Stripe normalization rejects malformed session metadata before PostgreSQL casts", () => {
  const normalized = normalizedStripeEvent({
    id: "evt_1",
    type: "payment_intent.succeeded",
    created: 10,
    data: { object: { id: "pi_1", status: "succeeded", metadata: { booking_session_id: "not-a-uuid" } } },
  });
  assert.equal(normalized.bookingSessionId, null);
  assert.equal(normalized.paymentIntentId, "pi_1");
  assert.equal(normalized.bookingType, "flight");
});

test("Stripe normalization preserves explicit Hotel booking ownership", () => {
  const normalized = normalizedStripeEvent({
    id: "evt_hotel", type: "payment_intent.succeeded", created: 10,
    data: { object: { id: "pi_hotel", status: "succeeded", metadata: { booking_session_id: SESSION_ID, booking_type: "hotel" } } },
  });
  assert.equal(normalized.bookingType, "hotel");
});

test("Hotel PaymentIntent webhook advances only the authoritative Hotel session", async () => {
  let hotelStatus = "awaiting_payment";
  const pool = { async connect() { return { async query(sql) {
    const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
    if (["begin", "commit", "rollback"].includes(normalized)) return { rows: [] };
    if (normalized.startsWith("insert into stripe_webhook_events")) return { rows: [{ event_id: "evt_hotel_success" }] };
    if (normalized.startsWith("update hotel_booking_sessions")) {
      hotelStatus = "payment_paid";
      return { rows: [{ id: SESSION_ID, booking_status: hotelStatus }] };
    }
    if (normalized.startsWith("update stripe_webhook_events")) return { rows: [] };
    throw new Error(`unexpected SQL: ${normalized}`);
  }, release() {} }; } };
  const result = await processStripeEvent(pool, {
    eventId: "evt_hotel_success", eventType: "payment_intent.succeeded", eventCreated: 10,
    objectId: "pi_hotel", bookingSessionId: SESSION_ID, bookingType: "hotel", paymentIntentId: "pi_hotel",
    status: "succeeded", amount: 13_500, currency: "CAD",
  });
  assert.equal(result.result, "payment:payment_paid");
  assert.equal(hotelStatus, "payment_paid");
});

function webhookPool() {
  const eventIds = new Set();
  const state = {
    booking_status: "awaiting_payment",
    stripe_payment_status: "requires_payment_method",
    stripe_payment_last_event_created: 0,
    stripe_refund_last_event_created: 0,
  };
  return {
    state,
    async connect() {
      return {
        async query(sql, params = []) {
          const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
          if (["begin", "commit", "rollback"].includes(normalized)) return { rows: [] };
          if (normalized.startsWith("insert into stripe_webhook_events")) {
            if (eventIds.has(params[0])) return { rows: [] };
            eventIds.add(params[0]);
            return { rows: [{ event_id: params[0] }] };
          }
          if (normalized.startsWith("update flight_booking_sessions") && normalized.includes("stripe_payment_status")) {
            const created = Number(params[3]);
            if (created <= state.stripe_payment_last_event_created) return { rows: [] };
            const succeeded = params[4];
            const authoritativeMatch = Number(params[6]) === 12_299 && params[7] === "USD";
            const nonSucceededAllowed = !succeeded
              && ["payment_setup", "awaiting_payment"].includes(state.booking_status)
              && state.stripe_payment_status !== "succeeded";
            const successAllowed = succeeded
              && ["payment_setup", "awaiting_payment", "payment_paid"].includes(state.booking_status)
              && authoritativeMatch;
            if (!(succeeded ? successAllowed : nonSucceededAllowed)) return { rows: [] };
            state.stripe_payment_last_event_created = created;
            state.stripe_payment_status = params[2];
            if (params[4] && ["payment_setup", "awaiting_payment"].includes(state.booking_status)) state.booking_status = "payment_paid";
            if (params[5] && ["payment_setup", "awaiting_payment"].includes(state.booking_status)) state.booking_status = "payment_canceled";
            return { rows: [{ id: SESSION_ID, booking_status: state.booking_status }] };
          }
          if (normalized.startsWith("update flight_booking_sessions") && normalized.includes("stripe_refund_id")) {
            const created = Number(params[4]);
            if (created <= state.stripe_refund_last_event_created || state.booking_status !== "booking_failed_refund_pending") return { rows: [] };
            state.stripe_refund_last_event_created = created;
            if (params[3]) state.booking_status = "booking_failed_refunded";
            return { rows: [{ id: SESSION_ID, booking_status: state.booking_status }] };
          }
          if (normalized.startsWith("insert into flight_booking_recovery_jobs")) return { rows: [] };
          if (normalized.startsWith("update stripe_webhook_events")) return { rows: [] };
          throw new Error(`unexpected SQL: ${normalized}`);
        },
        release() {},
      };
    },
  };
}

test("Stripe event ledger is idempotent and older events cannot regress booking state", async () => {
  const pool = webhookPool();
  const succeeded = {
    eventId: "evt_success", eventType: "payment_intent.succeeded", eventCreated: 20,
    objectId: "pi_1", bookingSessionId: SESSION_ID, paymentIntentId: "pi_1", status: "succeeded", amount: 12_299, currency: "USD",
  };
  const first = await processStripeEvent(pool, succeeded);
  const duplicate = await processStripeEvent(pool, succeeded);
  const older = await processStripeEvent(pool, {
    ...succeeded, eventId: "evt_old_cancel", eventType: "payment_intent.canceled", eventCreated: 10, status: "canceled",
  });
  const laterFailure = await processStripeEvent(pool, {
    ...succeeded, eventId: "evt_later_failure", eventType: "payment_intent.payment_failed", eventCreated: 30, status: "requires_payment_method",
  });
  const equalTimestamp = await processStripeEvent(pool, {
    ...succeeded, eventId: "evt_equal", eventType: "payment_intent.canceled", eventCreated: 20, status: "canceled",
  });
  assert.equal(first.duplicate, false);
  assert.equal(duplicate.duplicate, true);
  assert.equal(older.result, "payment:no_change");
  assert.equal(laterFailure.result, "payment:no_change");
  assert.equal(equalTimestamp.result, "payment:no_change");
  assert.equal(pool.state.booking_status, "payment_paid");
  assert.equal(pool.state.stripe_payment_status, "succeeded");
  assert.equal(pool.state.stripe_payment_last_event_created, 20);
});

test("PaymentIntent and refund event clocks do not suppress each other", async () => {
  const pool = webhookPool();
  await processStripeEvent(pool, {
    eventId: "evt_payment_newer", eventType: "payment_intent.succeeded", eventCreated: 200,
    objectId: "pi_1", bookingSessionId: SESSION_ID, paymentIntentId: "pi_1", status: "succeeded",
    amount: 12_299, currency: "USD",
  });
  pool.state.booking_status = "booking_failed_refund_pending";
  const refund = await processStripeEvent(pool, {
    eventId: "evt_refund_older", eventType: "refund.updated", eventCreated: 100,
    objectId: "re_1", bookingSessionId: SESSION_ID, paymentIntentId: "pi_1", status: "succeeded",
    amount: 12_299, currency: "USD",
  });
  assert.equal(refund.result, "refund:booking_failed_refunded");
  assert.equal(pool.state.stripe_payment_last_event_created, 200);
  assert.equal(pool.state.stripe_refund_last_event_created, 100);
});

test("succeeded PaymentIntent events do not refence advanced booking states", async () => {
  for (const bookingStatus of ["booking_in_progress", "booking_unknown", "booking_failed_refund_pending", "booking_failed_refunded", "confirmed"]) {
    const pool = webhookPool();
    pool.state.booking_status = bookingStatus;
    const result = await processStripeEvent(pool, {
      eventId: `evt_${bookingStatus}`, eventType: "payment_intent.succeeded", eventCreated: 50,
      objectId: "pi_1", bookingSessionId: SESSION_ID, paymentIntentId: "pi_1", status: "succeeded",
      amount: 12_299, currency: "USD",
    });
    assert.equal(result.result, "payment:no_change");
    assert.equal(pool.state.booking_status, bookingStatus);
    assert.equal(pool.state.stripe_payment_last_event_created, 0);
  }
});

test("Stripe success with mismatched authoritative amount records no change", async () => {
  const pool = webhookPool();
  const result = await processStripeEvent(pool, {
    eventId: "evt_wrong_amount", eventType: "payment_intent.succeeded", eventCreated: 40,
    objectId: "pi_1", bookingSessionId: SESSION_ID, paymentIntentId: "pi_1", status: "succeeded",
    amount: 1, currency: "USD",
  });
  assert.equal(result.result, "payment:no_change");
  assert.equal(pool.state.booking_status, "awaiting_payment");
  assert.equal(pool.state.stripe_payment_status, "requires_payment_method");
});

function responseRecorder() {
  return {
    statusCode: 200,
    payload: null,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; return this; },
  };
}

test("Stripe webhook verifies the signature against the untouched raw body", async () => {
  const rawBody = Buffer.from("{\"id\":\"evt_raw\"}");
  let receivedBody;
  const stripe = { webhooks: { constructEvent(body) {
    receivedBody = body;
    throw new Error("bad signature");
  } } };
  const handler = createStripeWebhookHandler({ stripe, webhookSecret: "whsec_test", dbPool: {} });
  const response = responseRecorder();
  await handler({ body: rawBody, headers: { "stripe-signature": "invalid" } }, response);
  assert.equal(receivedBody, rawBody);
  assert.equal(response.statusCode, 400);
  assert.equal(response.payload.error, "Invalid Stripe webhook signature");
});

test("Stripe webhook rejects test events on the live endpoint before database processing", async () => {
  const event = {
    id: "evt_test_on_live",
    type: "payment_intent.succeeded",
    created: 10,
    data: { object: { id: "pi_1", livemode: false, status: "succeeded", amount: 12_299, currency: "usd" } },
  };
  const stripe = { webhooks: { constructEvent() { return event; } } };
  const dbPool = { connect() { throw new Error("database must not be reached"); } };
  const handler = createStripeWebhookHandler({ stripe, webhookSecret: "whsec_live", dbPool, bookingMode: "live" });
  const response = responseRecorder();
  await handler({ body: Buffer.from("{}"), headers: { "stripe-signature": "valid" } }, response);
  assert.equal(response.statusCode, 400);
  assert.equal(response.payload.error, "Stripe webhook mode mismatch");
});

test("charge events ingest the actual Stripe fee from the balance transaction", async () => {
  let captured;
  const dbPool = {
    async connect() {
      return {
        async query(sql, params = []) {
          const normalized = sql.replace(/\s+/g, " ").trim().toLowerCase();
          if (["begin", "commit", "rollback"].includes(normalized)) return { rows: [] };
          if (normalized.startsWith("insert into stripe_webhook_events")) return { rows: [{ event_id: params[0] }] };
          if (normalized.startsWith("update flight_booking_sessions") && normalized.includes("stripe_actual_processing_minor")) {
            captured = params;
            return { rows: [{ id: SESSION_ID }] };
          }
          if (normalized.startsWith("update stripe_webhook_events")) return { rows: [] };
          throw new Error(`unexpected SQL: ${normalized}`);
        },
        release() {},
      };
    },
  };
  const event = {
    id: "evt_charge",
    type: "charge.succeeded",
    created: 20,
    data: { object: {
      id: "ch_1", livemode: false, payment_intent: "pi_1", balance_transaction: "txn_1",
      status: "succeeded", amount: 12_299, currency: "usd",
    } },
  };
  const stripe = {
    webhooks: { constructEvent() { return event; } },
    balanceTransactions: { async retrieve(id) {
      assert.equal(id, "txn_1");
      return { fee: 461, currency: "usd" };
    } },
  };
  const handler = createStripeWebhookHandler({ stripe, webhookSecret: "whsec_test", dbPool, bookingMode: "test" });
  const response = responseRecorder();
  await handler({ body: Buffer.from("{}"), headers: { "stripe-signature": "valid" } }, response);
  assert.equal(response.statusCode, 200);
  assert.equal(captured[0], "pi_1");
  assert.equal(captured[1], "ch_1");
  assert.equal(captured[2], "txn_1");
  assert.equal(captured[3], 461);
  assert.equal(captured[4], "USD");
  assert.equal(captured[6], 12_299);
  assert.equal(captured[7], "USD");
});
