const test = require("node:test");
const assert = require("node:assert/strict");

const {
  claimRecoveryJobs,
  completeClaimedJob,
  createFlightRecoveryService,
  enqueueRecoveryJob,
  recoverStaleBookingClaim,
  repairRecoveryJobs,
  retryDelayMs,
  validateRefundForSession,
  validateReconciledOrder,
} = require("../lib/flightRecovery");

const SESSION_ID = "11111111-1111-4111-8111-111111111111";

test("stale claim recovery is CAS-safe and never retries a post-marker booking", async () => {
  const calls = [];
  const preMarker = { id: SESSION_ID, booking_status: "payment_paid", duffel_post_started_at: null };
  const pool = { query: async (sql) => {
    calls.push(sql);
    if (sql.includes("duffel_post_started_at is null")) return { rows: [preMarker] };
    throw new Error("post-marker transition must not run after safe recovery");
  } };
  const safe = await recoverStaleBookingClaim(pool, { sessionId: SESSION_ID, leaseMs: 1234 });
  assert.equal(safe.disposition, "safe_retry");
  assert.equal(safe.session.booking_status, "payment_paid");
  assert.equal(calls.length, 1);

  const unknownPool = { query: async (sql) => {
    if (sql.includes("duffel_post_started_at is null")) return { rows: [] };
    if (sql.includes("duffel_post_started_at is not null")) {
      return { rows: [{ id: SESSION_ID, booking_status: "booking_unknown" }] };
    }
    throw new Error("unexpected query");
  } };
  const unknown = await recoverStaleBookingClaim(unknownPool, { sessionId: SESSION_ID });
  assert.equal(unknown.disposition, "outcome_unknown");
});

test("enqueue preserves an active claim and job claiming is exclusive", async () => {
  let enqueueSQL = "";
  await enqueueRecoveryJob({ query: async (sql) => { enqueueSQL = sql; return { rows: [] }; } }, SESSION_ID, "duffel_reconcile");
  assert.match(enqueueSQL, /claim_expires_at > now\(\) then 'claimed'/);
  assert.match(enqueueSQL, /status = 'manual_review' then 'manual_review'/);

  let claimed = false;
  const pool = {
    async connect() {
      return {
        async query(sql, params) {
          const normalized = sql.trim().toLowerCase();
          if (["begin", "commit", "rollback"].includes(normalized)) return { rows: [] };
          if (normalized.startsWith("with candidates")) {
            if (claimed) return { rows: [] };
            claimed = true;
            return { rows: [{ booking_session_id: SESSION_ID, kind: "stuck_claim", claim_token: params[1], attempt_count: 1 }] };
          }
          throw new Error(`unexpected query: ${normalized}`);
        },
        release() {},
      };
    },
  };
  const [first, second] = await Promise.all([
    claimRecoveryJobs(pool, { workerId: "one", makeToken: () => "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }),
    claimRecoveryJobs(pool, { workerId: "two", makeToken: () => "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" }),
  ]);
  assert.equal(first.length + second.length, 1);
});

test("claim completion is fenced and restart repair scans durable states", async () => {
  const calls = [];
  const pool = { query: async (sql, params) => {
    calls.push({ sql, params });
    if (sql.startsWith("update flight_booking_recovery_jobs")) return { rows: [] };
    return { rows: [{ booking_session_id: SESSION_ID, kind: "refund_reconcile" }] };
  } };
  const fenced = await completeClaimedJob(pool, {
    booking_session_id: SESSION_ID,
    kind: "refund_reconcile",
    claim_token: "stale-token",
  });
  assert.equal(fenced.fenced, true);
  const repaired = await repairRecoveryJobs(pool, { leaseMs: 9000 });
  assert.equal(repaired.length, 1);
  assert.match(calls[1].sql, /booking_failed_refund_pending/);
  assert.match(calls[1].sql, /status = 'completed'/);
  assert.doesNotMatch(calls[1].sql, /completed','manual_review/);
});

test("unconfigured Duffel lookup backs off to manual review without any order POST", async () => {
  let createOrderCalls = 0;
  let retryParams;
  const session = { id: SESSION_ID, booking_status: "booking_unknown" };
  const pool = { query: async (sql, params) => {
    if (sql === "select * from flight_booking_sessions where id = $1") return { rows: [session] };
    if (sql.includes("set status = $4")) {
      retryParams = params;
      return { rows: [{ status: params[3] }] };
    }
    throw new Error("automatic Duffel order activity is forbidden");
  } };
  const service = createFlightRecoveryService({
    dbPool: pool,
    stripe: null,
    duffelLookup: { createOrder: async () => { createOrderCalls += 1; } },
    buildConfirmation: () => ({}),
    jobOptions: { maximumAttempts: 12 },
  });
  const result = await service.processJob({
    booking_session_id: SESSION_ID,
    kind: "duffel_reconcile",
    claim_token: "claim",
    attempt_count: 12,
  });
  assert.equal(result.manual, true);
  assert.equal(retryParams[3], "manual_review");
  assert.equal(createOrderCalls, 0);
});

test("Duffel reconciliation requires authoritative facts and matches service-inclusive totals across currency exponents", () => {
  const session = {
    id: SESSION_ID,
    stripe_payment_intent_id: "pi_exact",
    duffel_offer_id: "off_exact",
    currency: "USD",
    duffel_total_minor: "12345",
    offer_snapshot: { total_amount: "120.00" },
  };
  const order = {
    id: "ord_exact",
    live_mode: false,
    offer_id: "off_exact",
    total_currency: "USD",
    total_amount: "123.450",
    metadata: {
      zippi_booking_session_id: SESSION_ID,
      stripe_payment_intent_id: "pi_exact",
      zippi_duffel_offer_id: "off_exact",
      zippi_currency: "usd",
      zippi_duffel_total_minor: "12345",
    },
  };
  assert.equal(validateReconciledOrder(order, session), true);
  assert.equal(validateReconciledOrder(order, { ...session, stripe_payment_intent_id: null }), false);
  for (const [key, value] of Object.entries({ live_mode: true, offer_id: "off_other", total_currency: "CAD", total_amount: "123.46" })) {
    assert.equal(validateReconciledOrder({ ...order, [key]: value }, session), false, `${key} must match`);
  }
  const currencyCases = [
    { currency: "JPY", amount: "120", minor: "120" },
    { currency: "KWD", amount: "1.234", minor: "1234" },
  ];
  for (const item of currencyCases) {
    assert.equal(validateReconciledOrder({
      ...order,
      total_currency: item.currency,
      total_amount: item.amount,
      metadata: {
        ...order.metadata,
        zippi_currency: item.currency,
        zippi_duffel_total_minor: item.minor,
      },
    }, {
      ...session,
      currency: item.currency,
      duffel_total_minor: item.minor,
    }), true);
  }
  for (const key of ["zippi_booking_session_id", "stripe_payment_intent_id"]) {
    const missing = { ...order, metadata: { ...order.metadata } };
    delete missing.metadata[key];
    assert.equal(validateReconciledOrder(missing, session), false, `${key} is required`);
  }
  const legacyMetadata = { ...order, metadata: {
    zippi_booking_session_id: SESSION_ID,
    stripe_payment_intent_id: "pi_exact",
  } };
  assert.equal(validateReconciledOrder(legacyMetadata, session), true, "pre-004 TEST order metadata remains recoverable");
  for (const key of Object.keys(order.metadata)) {
    if (key === "zippi_currency") continue;
    const mismatch = { ...order, metadata: { ...order.metadata, [key]: "mismatch" } };
    assert.equal(validateReconciledOrder(mismatch, session), false, `${key} must match`);
  }
});

test("a reconciled confirmation clears the recovery marker", async () => {
  const session = {
    id: SESSION_ID,
    booking_status: "booking_unknown",
    stripe_payment_intent_id: "pi_exact",
    duffel_offer_id: "off_exact",
    currency: "USD",
    duffel_total_minor: "12345",
  };
  const order = {
    id: "ord_exact",
    booking_reference: "ABC123",
    live_mode: false,
    offer_id: "off_exact",
    total_currency: "USD",
    total_amount: "123.45",
    metadata: {
      zippi_booking_session_id: SESSION_ID,
      stripe_payment_intent_id: "pi_exact",
      zippi_duffel_offer_id: "off_exact",
      zippi_currency: "USD",
      zippi_duffel_total_minor: "12345",
    },
  };
  let confirmationSQL = "";
  const pool = { query: async (sql) => {
    if (sql === "select * from flight_booking_sessions where id = $1") return { rows: [session] };
    confirmationSQL = sql;
    return { rows: [{ ...session, booking_status: "confirmed", recovery_status: null }] };
  } };
  const service = createFlightRecoveryService({
    dbPool: pool,
    stripe: null,
    duffelLookup: { findOrderForSession: async () => ({ status: "found", order }) },
    buildConfirmation: () => ({ orderId: order.id }),
  });
  const result = await service.reconcileDuffel({ booking_session_id: SESSION_ID });
  assert.equal(result.completed, true);
  assert.match(confirmationSQL, /recovery_status = null/);
});

test("refund recovery reuses one deterministic Stripe idempotency key after a crash", async () => {
  const keys = [];
  const session = {
    id: SESSION_ID,
    booking_status: "booking_failed_refund_pending",
    stripe_payment_intent_id: "pi_refund",
    stripe_refund_id: null,
    failure_code: "offer_unavailable",
    currency: "USD",
    charge_total_minor: "12345",
  };
  const pool = { query: async (sql) => {
    if (sql === "select * from flight_booking_sessions where id = $1") return { rows: [session] };
    if (sql.includes("booking_failed_refund_pending")) return { rows: [session] };
    throw new Error("unexpected query");
  } };
  const stripe = { refunds: { create: async (_payload, options) => {
    keys.push(options.idempotencyKey);
    return {
      id: "re_same",
      status: "succeeded",
      payment_intent: "pi_refund",
      currency: "usd",
      amount: 12345,
      metadata: { booking_session_id: SESSION_ID },
    };
  } } };
  const service = createFlightRecoveryService({ dbPool: pool, stripe, buildConfirmation: () => ({}) });
  await service.reconcileRefund({ booking_session_id: SESSION_ID });
  await service.reconcileRefund({ booking_session_id: SESSION_ID });
  assert.deepEqual(keys, [`flight-refund-${SESSION_ID}`, `flight-refund-${SESSION_ID}`]);
});

test("refund recovery accepts only the full authoritative booking refund", () => {
  const session = {
    id: SESSION_ID,
    stripe_payment_intent_id: "pi_refund",
    currency: "USD",
    charge_total_minor: "12345",
  };
  const refund = {
    id: "re_exact",
    status: "succeeded",
    payment_intent: "pi_refund",
    currency: "usd",
    amount: 12345,
    metadata: { booking_session_id: SESSION_ID },
  };
  assert.equal(validateRefundForSession(refund, session), true);
  assert.equal(validateRefundForSession({ ...refund, amount: 100 }, session), false);
  assert.equal(validateRefundForSession({ ...refund, payment_intent: "pi_other" }, session), false);
  assert.equal(validateRefundForSession({ ...refund, currency: "cad" }, session), false);
  assert.equal(validateRefundForSession({ ...refund, metadata: {} }, session), false);
});

test("refund worker never completes a partial persisted refund", async () => {
  const session = {
    id: SESSION_ID,
    booking_status: "booking_failed_refund_pending",
    stripe_payment_intent_id: "pi_refund",
    stripe_refund_id: "re_partial",
    currency: "USD",
    charge_total_minor: "12345",
  };
  let updateCount = 0;
  const pool = { query: async (sql) => {
    if (sql === "select * from flight_booking_sessions where id = $1") return { rows: [session] };
    updateCount += 1;
    return { rows: [session] };
  } };
  const stripe = { refunds: { retrieve: async () => ({
    id: "re_partial",
    status: "succeeded",
    payment_intent: "pi_refund",
    currency: "usd",
    amount: 100,
    metadata: { booking_session_id: SESSION_ID },
  }) } };
  const service = createFlightRecoveryService({ dbPool: pool, stripe, buildConfirmation: () => ({}) });
  await assert.rejects(
    service.reconcileRefund({ booking_session_id: SESSION_ID }),
    /does not authoritatively match/
  );
  assert.equal(updateCount, 0);
});

test("recovery backoff is bounded and exponential", () => {
  assert.equal(retryDelayMs(1, 1000, 5000), 1000);
  assert.equal(retryDelayMs(3, 1000, 5000), 4000);
  assert.equal(retryDelayMs(20, 1000, 5000), 5000);
});
