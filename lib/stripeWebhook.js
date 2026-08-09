const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function normalizedBookingSessionId(value) {
  const candidate = String(value || "").trim();
  return UUID_PATTERN.test(candidate) ? candidate : null;
}

function normalizedStripeEvent(event) {
  const object = event?.data?.object || {};
  const metadata = object.metadata || {};
  const isRefund = String(event?.type || "").startsWith("refund.");
  const isCharge = String(event?.type || "").startsWith("charge.");
  return {
    eventId: String(event?.id || ""),
    eventType: String(event?.type || ""),
    eventCreated: Number(event?.created || 0),
    objectId: String(object.id || "") || null,
    bookingSessionId: normalizedBookingSessionId(metadata.booking_session_id),
    bookingType: String(metadata.booking_type || "flight").trim().toLowerCase() === "hotel" ? "hotel" : "flight",
    paymentIntentId: String((isRefund || isCharge) ? object.payment_intent || "" : object.id || "") || null,
    chargeId: String(isCharge ? object.id || "" : object.latest_charge || "") || null,
    balanceTransactionId: String(object.balance_transaction || "") || null,
    liveMode: object.livemode === true,
    status: String(object.status || "") || null,
    amount: Number.isFinite(object.amount) ? object.amount : null,
    currency: String(object.currency || "").toUpperCase() || null,
  };
}

function stripeEventPrecedence(normalized) {
  if (normalized.eventType === "payment_intent.succeeded" || normalized.status === "succeeded") return 100;
  if (normalized.eventType === "payment_intent.canceled" || normalized.status === "canceled") return 50;
  if (normalized.status === "processing" || normalized.status === "pending") return 20;
  if (normalized.status === "requires_action") return 15;
  return 10;
}

async function processStripeEvent(dbPool, normalized) {
  const isHotel = normalized.bookingType === "hotel";
  const sessionsTable = isHotel ? "hotel_booking_sessions" : "flight_booking_sessions";
  const amountColumn = isHotel ? "customer_total_minor" : "charge_total_minor";
  const currencyColumn = isHotel ? "customer_currency" : "currency";
  const recoveryJobsTable = isHotel ? "hotel_booking_recovery_jobs" : "flight_booking_recovery_jobs";
  const client = await dbPool.connect();
  try {
    await client.query("begin");
    const inserted = await client.query(
      `insert into stripe_webhook_events (
         event_id, event_type, object_id, booking_session_id, event_created, normalized_payload
       ) values ($1,$2,$3,$4,$5,$6::jsonb)
       on conflict (event_id) do nothing
       returning event_id`,
      [normalized.eventId, normalized.eventType, normalized.objectId, normalized.bookingSessionId,
        normalized.eventCreated, JSON.stringify(normalized)]
    );
    if (!inserted.rows[0]) {
      await client.query("commit");
      return { duplicate: true, result: "duplicate" };
    }

    let result = "ignored";
    if (normalized.eventType.startsWith("payment_intent.")) {
      const succeeded = normalized.eventType === "payment_intent.succeeded";
      const canceled = normalized.eventType === "payment_intent.canceled";
      const precedence = stripeEventPrecedence(normalized);
      const updated = await client.query(
        `update ${sessionsTable} set
           stripe_payment_status = $3,
           stripe_payment_last_event_created = $4,
           stripe_payment_last_event_precedence = $9,
           stripe_payment_last_event_id = $10,
           booking_status = case
             when $5 and booking_status in ('payment_setup','awaiting_payment') then 'payment_paid'
             when $6 and booking_status in ('payment_setup','awaiting_payment') then 'payment_canceled'
             else booking_status end,
           updated_at = now()
         where stripe_payment_intent_id = $1
           and ($2::uuid is null or id = $2)
           and (
             stripe_payment_last_event_created < $4
             or (stripe_payment_last_event_created = $4 and stripe_payment_last_event_precedence < $9)
             or (stripe_payment_last_event_created = $4 and stripe_payment_last_event_precedence = $9
                 and coalesce(stripe_payment_last_event_id, '') < $10)
           )
           and (
             ($5 and booking_status in ('payment_setup','awaiting_payment','payment_paid')
                 and $7 = ${amountColumn} and $8 = ${currencyColumn})
             or (not $5 and booking_status in ('payment_setup','awaiting_payment')
                 and coalesce(stripe_payment_status, '') <> 'succeeded')
           )
         returning id, booking_status`,
        [normalized.paymentIntentId, normalized.bookingSessionId, normalized.status || normalized.eventType,
          normalized.eventCreated, succeeded, canceled, normalized.amount, normalized.currency,
          precedence, normalized.eventId]
      );
      result = updated.rows[0] ? `payment:${updated.rows[0].booking_status}` : "payment:no_change";
    } else if (!isHotel && normalized.eventType.startsWith("charge.")
        && normalized.actualFeeMinor != null && normalized.actualFeeCurrency) {
      const updated = await client.query(
        `update flight_booking_sessions set
           stripe_charge_id = coalesce(stripe_charge_id, $2),
           stripe_balance_transaction_id = coalesce(stripe_balance_transaction_id, $3),
           stripe_actual_processing_minor = $4,
           stripe_actual_processing_currency = $5,
           stripe_fee_reconciled_at = now(), updated_at = now()
         where stripe_payment_intent_id = $1
           and ($6::uuid is null or id = $6)
           and $7 = charge_total_minor and $8 = currency
         returning id`,
        [normalized.paymentIntentId, normalized.chargeId, normalized.balanceTransactionId,
          normalized.actualFeeMinor, normalized.actualFeeCurrency,
          normalized.bookingSessionId, normalized.amount, normalized.currency]
      );
      result = updated.rows[0] ? "charge:fee_reconciled" : "charge:no_change";
    } else if (normalized.eventType.startsWith("refund.")) {
      const succeeded = normalized.status === "succeeded";
      const precedence = stripeEventPrecedence(normalized);
      const updated = await client.query(
        `update ${sessionsTable} set
           stripe_refund_id = coalesce(stripe_refund_id, $2),
           recovery_status = case when $4 then 'refunded' else 'refund_pending' end,
           booking_status = case when $4 then 'booking_failed_refunded' else booking_status end,
           stripe_refund_last_event_created = $5,
           stripe_refund_last_event_precedence = $8,
           stripe_refund_last_event_id = $9,
           booking_claim_token = case when $4 then null else booking_claim_token end,
           booking_claim_expires_at = case when $4 then null else booking_claim_expires_at end,
           updated_at = now()
         where booking_status = 'booking_failed_refund_pending'
           and stripe_payment_intent_id = $3
           and $6 = ${amountColumn} and $7 = ${currencyColumn}
           and (stripe_refund_id = $2 or (stripe_refund_id is null and $1::uuid is not null and id = $1))
           and (
             stripe_refund_last_event_created < $5
             or (stripe_refund_last_event_created = $5 and stripe_refund_last_event_precedence < $8)
             or (stripe_refund_last_event_created = $5 and stripe_refund_last_event_precedence = $8
                 and coalesce(stripe_refund_last_event_id, '') < $9)
           )
         returning id, booking_status`,
        [normalized.bookingSessionId, normalized.objectId, normalized.paymentIntentId, succeeded,
          normalized.eventCreated, normalized.amount, normalized.currency, precedence, normalized.eventId]
      );
      if (updated.rows[0] && !succeeded) {
        await client.query(
          `insert into ${recoveryJobsTable} (booking_session_id, kind)
           values ($1, 'refund_reconcile') on conflict (booking_session_id, kind) do nothing`,
          [updated.rows[0].id]
        );
      }
      result = updated.rows[0] ? `refund:${updated.rows[0].booking_status}` : "refund:no_change";
    }

    await client.query(
      "update stripe_webhook_events set processing_result = $2, processed_at = now() where event_id = $1",
      [normalized.eventId, result]
    );
    await client.query("commit");
    return { duplicate: false, result };
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function createStripeWebhookHandler({
  stripe,
  webhookSecret,
  dbPool,
  bookingMode = "test",
  configurations = null,
}) {
  const webhookConfigurations = (Array.isArray(configurations) ? configurations : [{
    stripe, webhookSecret, bookingMode, bookingTypes: ["flight", "hotel"],
  }]).filter((configuration) => configuration?.stripe && configuration?.webhookSecret);
  return async function stripeWebhookHandler(req, res) {
    if (!webhookConfigurations.length || !dbPool) {
      return res.status(503).json({ ok: false, error: "Stripe webhook is not configured" });
    }
    let matched = null;
    for (const configuration of webhookConfigurations) {
      try {
        const event = configuration.stripe.webhooks.constructEvent(
          req.body,
          req.headers["stripe-signature"],
          configuration.webhookSecret
        );
        const normalized = normalizedStripeEvent(event);
        const bookingTypes = configuration.bookingTypes || ["flight", "hotel"];
        if (bookingTypes.includes(normalized.bookingType)) {
          matched = { configuration, normalized };
          break;
        }
      } catch (_) {
        // A shared route may have independent Flight LIVE and Hotel TEST endpoints.
      }
    }
    if (!matched) {
      return res.status(400).json({ ok: false, error: "Invalid Stripe webhook signature" });
    }
    const { configuration, normalized } = matched;
    if (!normalized.eventId || !normalized.eventType || !Number.isSafeInteger(normalized.eventCreated)) {
      return res.status(400).json({ ok: false, error: "Invalid Stripe webhook event" });
    }
    if (normalized.liveMode !== (configuration.bookingMode === "live")) {
      return res.status(400).json({ ok: false, error: "Stripe webhook mode mismatch" });
    }
    try {
      if (normalized.eventType.startsWith("charge.") && normalized.balanceTransactionId) {
        const balanceTransaction = await configuration.stripe.balanceTransactions.retrieve(normalized.balanceTransactionId);
        if (Number.isSafeInteger(balanceTransaction?.fee)) {
          normalized.actualFeeMinor = balanceTransaction.fee;
          normalized.actualFeeCurrency = String(balanceTransaction.currency || "").toUpperCase() || null;
        }
      }
      const processed = await processStripeEvent(dbPool, normalized);
      return res.json({ received: true, duplicate: processed.duplicate });
    } catch (_) {
      return res.status(500).json({ ok: false, error: "Stripe webhook processing failed" });
    }
  };
}

module.exports = {
  createStripeWebhookHandler,
  normalizedBookingSessionId,
  normalizedStripeEvent,
  processStripeEvent,
  stripeEventPrecedence,
};
