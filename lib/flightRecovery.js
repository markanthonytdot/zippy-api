const { randomUUID } = require("node:crypto");
const { decimalToMinorExact } = require("./currencyAmount");

const JOB_KINDS = new Set(["stuck_claim", "duffel_reconcile", "refund_reconcile"]);

function providerCurrency(session) {
  return String(session?.provider_currency || session?.currency || "").toUpperCase();
}

function customerCurrency(session) {
  return String(session?.customer_currency || session?.currency || "").toUpperCase();
}

function providerTotalMinor(session) {
  return session?.provider_total_minor ?? session?.duffel_total_minor;
}

function customerTotalMinor(session) {
  return session?.customer_total_minor ?? session?.charge_total_minor;
}

function retryDelayMs(attemptCount, baseMs = 30_000, maximumMs = 6 * 60 * 60 * 1000) {
  const exponent = Math.max(0, Math.min(20, Number(attemptCount || 1) - 1));
  return Math.min(maximumMs, baseMs * (2 ** exponent));
}

async function recoverStaleBookingClaim(dbPool, { sessionId, leaseMs = 5 * 60 * 1000 }) {
  const safe = await dbPool.query(
    `update flight_booking_sessions
        set booking_status = 'payment_paid', recovery_status = 'safe_retry_ready',
            failure_code = 'stale_pre_order_claim',
            failure_message = 'A previous booking attempt stopped before airline submission and can be retried.',
            booking_claim_token = null, booking_claim_expires_at = null,
            updated_at = now()
      where id = $1 and booking_status = 'booking_in_progress'
        and duffel_post_started_at is null
        and updated_at < now() - ($2::bigint * interval '1 millisecond')
      returning *`,
    [sessionId, leaseMs]
  );
  if (safe.rows[0]) return { disposition: "safe_retry", session: safe.rows[0] };

  const unknown = await dbPool.query(
    `update flight_booking_sessions
        set booking_status = 'booking_unknown', recovery_status = 'manual_reconciliation_required',
            failure_code = 'stale_post_attempt',
            failure_message = 'The airline order attempt needs reconciliation.',
            booking_claim_token = null, booking_claim_expires_at = null, updated_at = now()
      where id = $1 and booking_status = 'booking_in_progress'
        and duffel_post_started_at is not null
        and updated_at < now() - ($2::bigint * interval '1 millisecond')
      returning *`,
    [sessionId, leaseMs]
  );
  if (unknown.rows[0]) return { disposition: "outcome_unknown", session: unknown.rows[0] };
  const current = await dbPool.query("select * from flight_booking_sessions where id = $1", [sessionId]);
  return { disposition: "unchanged", session: current.rows[0] || null };
}

async function enqueueRecoveryJob(dbPool, bookingSessionId, kind) {
  if (!JOB_KINDS.has(kind)) throw new Error(`Unsupported flight recovery job kind: ${kind}`);
  await dbPool.query(
    `insert into flight_booking_recovery_jobs (booking_session_id, kind)
     values ($1, $2)
     on conflict (booking_session_id, kind) do update
       set status = case
             when flight_booking_recovery_jobs.status = 'claimed'
               and flight_booking_recovery_jobs.claim_expires_at > now() then 'claimed'
             when flight_booking_recovery_jobs.status = 'manual_review' then 'manual_review'
             else 'queued'
           end,
           available_at = case when flight_booking_recovery_jobs.status = 'completed'
             then flight_booking_recovery_jobs.available_at else least(flight_booking_recovery_jobs.available_at, now()) end,
           claim_token = case when flight_booking_recovery_jobs.status = 'claimed'
             and flight_booking_recovery_jobs.claim_expires_at > now() then flight_booking_recovery_jobs.claim_token else null end,
           claimed_by = case when flight_booking_recovery_jobs.status = 'claimed'
             and flight_booking_recovery_jobs.claim_expires_at > now() then flight_booking_recovery_jobs.claimed_by else null end,
           claim_expires_at = case when flight_booking_recovery_jobs.status = 'claimed'
             and flight_booking_recovery_jobs.claim_expires_at > now() then flight_booking_recovery_jobs.claim_expires_at else null end,
           attempt_count = case when flight_booking_recovery_jobs.status = 'completed'
             then 0 else flight_booking_recovery_jobs.attempt_count end,
           last_error = case when flight_booking_recovery_jobs.status = 'completed'
             then null else flight_booking_recovery_jobs.last_error end,
           updated_at = now()
     where flight_booking_recovery_jobs.status <> 'completed'
        or exists (
          select 1 from flight_booking_sessions sessions
          where sessions.id = $1 and (
            ($2 = 'stuck_claim' and sessions.booking_status = 'booking_in_progress')
            or ($2 = 'duffel_reconcile' and sessions.booking_status = 'booking_unknown')
            or ($2 = 'refund_reconcile' and sessions.booking_status = 'booking_failed_refund_pending')
          )
        )`,
    [bookingSessionId, kind]
  );
}

async function repairRecoveryJobs(dbPool, { leaseMs = 5 * 60 * 1000 } = {}) {
  const result = await dbPool.query(
    `insert into flight_booking_recovery_jobs (booking_session_id, kind)
     select id, case
       when booking_status = 'booking_in_progress' then 'stuck_claim'
       when booking_status = 'booking_unknown' then 'duffel_reconcile'
       else 'refund_reconcile'
     end
     from flight_booking_sessions
     where (booking_status = 'booking_in_progress'
              and updated_at < now() - ($1::bigint * interval '1 millisecond'))
        or booking_status in ('booking_unknown', 'booking_failed_refund_pending')
     on conflict (booking_session_id, kind) do update
       set status = 'queued', available_at = now(), attempt_count = 0,
           claim_token = null, claimed_by = null, claim_expires_at = null,
           last_error = null, updated_at = now()
       where flight_booking_recovery_jobs.status = 'completed'
     returning booking_session_id, kind`,
    [leaseMs]
  );
  return result.rows;
}

async function claimRecoveryJobs(dbPool, {
  workerId,
  limit = 10,
  leaseMs = 60_000,
  makeToken = randomUUID,
} = {}) {
  const client = await dbPool.connect();
  try {
    await client.query("begin");
    const token = makeToken();
    const result = await client.query(
      `with candidates as (
         select booking_session_id, kind
         from flight_booking_recovery_jobs
         where (status = 'queued' and available_at <= now())
            or (status = 'claimed' and claim_expires_at <= now())
         order by available_at, booking_session_id, kind
         for update skip locked
         limit $1
       )
       update flight_booking_recovery_jobs jobs
          set status = 'claimed', claim_token = $2, claimed_by = $3,
              claim_expires_at = now() + ($4::bigint * interval '1 millisecond'),
              attempt_count = jobs.attempt_count + 1, updated_at = now()
       from candidates
       where jobs.booking_session_id = candidates.booking_session_id and jobs.kind = candidates.kind
       returning jobs.*`,
      [limit, token, String(workerId || "flight-recovery-worker"), leaseMs]
    );
    await client.query("commit");
    return result.rows;
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function completeClaimedJob(dbPool, job, result = "completed") {
  const updated = await dbPool.query(
    `update flight_booking_recovery_jobs
        set status = 'completed', claim_token = null, claimed_by = null, claim_expires_at = null,
            last_error = null, updated_at = now()
      where booking_session_id = $1 and kind = $2 and status = 'claimed' and claim_token = $3
      returning *`,
    [job.booking_session_id, job.kind, job.claim_token]
  );
  return { fenced: !updated.rows[0], result };
}

async function retryClaimedJob(dbPool, job, error, {
  maximumAttempts = 12,
  baseDelayMs = 30_000,
  maximumDelayMs = 6 * 60 * 60 * 1000,
} = {}) {
  const manual = Number(job.attempt_count) >= maximumAttempts;
  const delayMs = retryDelayMs(job.attempt_count, baseDelayMs, maximumDelayMs);
  const updated = await dbPool.query(
    `update flight_booking_recovery_jobs
        set status = $4, available_at = now() + ($5::bigint * interval '1 millisecond'),
            claim_token = null, claimed_by = null, claim_expires_at = null,
            last_error = $6, updated_at = now()
      where booking_session_id = $1 and kind = $2 and status = 'claimed' and claim_token = $3
      returning *`,
    [job.booking_session_id, job.kind, job.claim_token, manual ? "manual_review" : "queued", delayMs,
      String(error?.message || error || "Recovery attempt failed").slice(0, 500)]
  );
  return { fenced: !updated.rows[0], manual, delayMs };
}

function validateReconciledOrder(order, session) {
  if (!order?.id) return false;
  const metadata = order.metadata || {};
  if (!session?.id || !session.stripe_payment_intent_id || !session.duffel_offer_id
      || !providerCurrency(session) || providerTotalMinor(session) == null) return false;
  let orderTotalMinor;
  try {
    orderTotalMinor = decimalToMinorExact(order.total_amount, order.total_currency);
  } catch (_) {
    return false;
  }
  const optionalMetadataMatches = (key, expected, normalize = String) => {
    const actual = metadata[key];
    return actual == null || String(actual).trim() === "" || normalize(actual) === normalize(expected);
  };
  return order.live_mode === false
    && String(order.offer_id || "") === String(session.duffel_offer_id || "")
    && String(order.total_currency || "").toUpperCase() === providerCurrency(session)
    && String(orderTotalMinor) === String(providerTotalMinor(session))
    && String(metadata.zippi_booking_session_id || "") === String(session.id || "")
    && String(metadata.stripe_payment_intent_id || "") === String(session.stripe_payment_intent_id || "")
    // Orders made before recovery migration 004 contain only the two identifiers
    // above. New redundant facts must match when present, while the authoritative
    // order fields continue to validate legacy TEST orders safely.
    && optionalMetadataMatches("zippi_duffel_offer_id", session.duffel_offer_id)
    && optionalMetadataMatches("zippi_currency", providerCurrency(session), (value) => String(value).toUpperCase())
    && optionalMetadataMatches("zippi_duffel_total_minor", providerTotalMinor(session))
    && optionalMetadataMatches("zippi_customer_currency", customerCurrency(session), (value) => String(value).toUpperCase())
    && optionalMetadataMatches("zippi_customer_total_minor", customerTotalMinor(session));
}

function validateRefundForSession(refund, session) {
  const paymentIntentId = typeof refund?.payment_intent === "string"
    ? refund.payment_intent
    : refund?.payment_intent?.id;
  return Boolean(refund?.id)
    && refund.status === "succeeded"
    && String(paymentIntentId || "") === String(session?.stripe_payment_intent_id || "")
    && String(refund.currency || "").toUpperCase() === customerCurrency(session)
    && Number.isSafeInteger(refund.amount)
    && String(refund.amount) === String(customerTotalMinor(session))
    && String(refund.metadata?.booking_session_id || "") === String(session?.id || "");
}

function createFlightRecoveryService({
  dbPool,
  stripe,
  duffelLookup = null,
  buildConfirmation,
  leaseMs = 5 * 60 * 1000,
  jobOptions = {},
}) {
  async function loadSession(id) {
    const result = await dbPool.query("select * from flight_booking_sessions where id = $1", [id]);
    return result.rows[0] || null;
  }

  async function reconcileStuckClaim(job) {
    const outcome = await recoverStaleBookingClaim(dbPool, { sessionId: job.booking_session_id, leaseMs });
    if (outcome.session?.booking_status === "booking_unknown") {
      await enqueueRecoveryJob(dbPool, job.booking_session_id, "duffel_reconcile");
    }
    return { completed: outcome.disposition !== "unchanged" || outcome.session?.booking_status !== "booking_in_progress" };
  }

  async function reconcileDuffel(job) {
    const session = await loadSession(job.booking_session_id);
    if (!session || session.booking_status !== "booking_unknown") return { completed: true };
    if (!duffelLookup?.findOrderForSession) {
      throw new Error("Duffel read-only order reconciliation is not configured; manual review required");
    }
    const lookup = await duffelLookup.findOrderForSession(session);
    if (lookup?.status !== "found" || !validateReconciledOrder(lookup.order, session)) {
      throw new Error("Duffel order outcome remains unknown; no order retry or refund is permitted");
    }
    const confirmation = buildConfirmation(lookup.order, session);
    const updated = await dbPool.query(
      `update flight_booking_sessions set
         booking_status = 'confirmed', duffel_order_id = $2, duffel_booking_reference = $3,
         duffel_request_id = coalesce($4, duffel_request_id), confirmation_snapshot = $5::jsonb,
         recovery_status = null, confirmed_at = now(),
         failure_code = null, failure_message = null,
         booking_claim_token = null, booking_claim_expires_at = null, updated_at = now()
       where id = $1 and booking_status = 'booking_unknown'
       returning *`,
      [session.id, lookup.order.id, lookup.order.booking_reference || null, lookup.requestId || null,
        JSON.stringify(confirmation)]
    );
    return { completed: Boolean(updated.rows[0]) };
  }

  async function reconcileRefund(job) {
    const session = await loadSession(job.booking_session_id);
    if (!session || session.booking_status !== "booking_failed_refund_pending") return { completed: true };
    if (!stripe || !session.stripe_payment_intent_id) throw new Error("Stripe refund recovery is not configured");
    let refund;
    if (session.stripe_refund_id) {
      refund = await stripe.refunds.retrieve(session.stripe_refund_id);
    } else {
      refund = await stripe.refunds.create({
        payment_intent: session.stripe_payment_intent_id,
        reason: "requested_by_customer",
        metadata: { booking_session_id: session.id, failure_code: session.failure_code || "booking_failed" },
      }, { idempotencyKey: `flight-refund-${session.id}` });
    }
    const succeeded = validateRefundForSession(refund, session);
    if (refund.status === "succeeded" && !succeeded) {
      throw new Error("Stripe refund does not authoritatively match the full booking charge");
    }
    const updated = await dbPool.query(
      `update flight_booking_sessions set
         booking_status = case when $3 then 'booking_failed_refunded' else booking_status end,
         stripe_refund_id = coalesce(stripe_refund_id, $2),
         recovery_status = case when $3 then 'refunded' else 'refund_pending' end,
         booking_claim_token = case when $3 then null else booking_claim_token end,
         booking_claim_expires_at = case when $3 then null else booking_claim_expires_at end,
         updated_at = now()
       where id = $1 and booking_status = 'booking_failed_refund_pending'
       returning *`,
      [session.id, refund.id, succeeded]
    );
    if (!updated.rows[0]) return { completed: true };
    if (!succeeded) throw new Error(`Stripe refund is ${refund.status || "not complete"}`);
    return { completed: true };
  }

  async function processJob(job) {
    try {
      let outcome;
      if (job.kind === "stuck_claim") outcome = await reconcileStuckClaim(job);
      else if (job.kind === "duffel_reconcile") outcome = await reconcileDuffel(job);
      else if (job.kind === "refund_reconcile") outcome = await reconcileRefund(job);
      else throw new Error(`Unsupported recovery job kind: ${job.kind}`);
      if (!outcome.completed) throw new Error("Recovery state changed concurrently; retry required");
      return completeClaimedJob(dbPool, job);
    } catch (error) {
      return retryClaimedJob(dbPool, job, error, jobOptions);
    }
  }

  async function runOnce({ workerId, limit = 1, claimLeaseMs = 60_000 } = {}) {
    await repairRecoveryJobs(dbPool, { leaseMs });
    const jobs = await claimRecoveryJobs(dbPool, { workerId, limit, leaseMs: claimLeaseMs });
    const results = [];
    for (const job of jobs) results.push(await processJob(job));
    return { claimed: jobs.length, results };
  }

  return { processJob, reconcileDuffel, reconcileRefund, reconcileStuckClaim, runOnce };
}

module.exports = {
  JOB_KINDS,
  claimRecoveryJobs,
  completeClaimedJob,
  createFlightRecoveryService,
  enqueueRecoveryJob,
  recoverStaleBookingClaim,
  repairRecoveryJobs,
  retryClaimedJob,
  retryDelayMs,
  validateRefundForSession,
  validateReconciledOrder,
};
