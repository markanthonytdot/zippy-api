const { randomUUID } = require("node:crypto");

const JOB_KINDS = new Set(["stuck_claim", "duffel_reconcile", "refund_reconcile"]);

function customerCurrency(session) { return String(session?.customer_currency || "").toUpperCase(); }
function retryDelayMs(attemptCount, baseMs = 30_000, maximumMs = 6 * 60 * 60 * 1000) {
  const exponent = Math.max(0, Math.min(20, Number(attemptCount || 1) - 1));
  return Math.min(maximumMs, baseMs * (2 ** exponent));
}

async function recoverStaleBookingClaim(dbPool, { sessionId, leaseMs = 5 * 60 * 1000 }) {
  const safe = await dbPool.query(
    `update hotel_booking_sessions set booking_status='payment_paid', recovery_status='safe_retry_ready',
       failure_code='stale_pre_booking_claim', failure_message='A previous attempt stopped before Duffel submission and can be retried safely.',
       booking_claim_token=null, booking_claim_expires_at=null, updated_at=now()
     where id=$1 and booking_status='booking_in_progress' and duffel_post_started_at is null
       and updated_at < now() - ($2::bigint * interval '1 millisecond') returning *`,
    [sessionId, leaseMs]
  );
  if (safe.rows[0]) return { disposition: "safe_retry", session: safe.rows[0] };
  const unknown = await dbPool.query(
    `update hotel_booking_sessions set booking_status='booking_unknown', recovery_status='manual_reconciliation_required',
       failure_code='stale_post_attempt', failure_message='The Duffel Stays booking attempt requires read-only reconciliation.',
       booking_claim_token=null, booking_claim_expires_at=null, updated_at=now()
     where id=$1 and booking_status='booking_in_progress' and duffel_post_started_at is not null
       and updated_at < now() - ($2::bigint * interval '1 millisecond') returning *`,
    [sessionId, leaseMs]
  );
  if (unknown.rows[0]) return { disposition: "outcome_unknown", session: unknown.rows[0] };
  const current = await dbPool.query("select * from hotel_booking_sessions where id=$1", [sessionId]);
  return { disposition: "unchanged", session: current.rows[0] || null };
}

async function repairRecoveryJobs(dbPool, { leaseMs = 5 * 60 * 1000 } = {}) {
  const result = await dbPool.query(
    `insert into hotel_booking_recovery_jobs (booking_session_id, kind)
     select id, case when booking_status='booking_in_progress' then 'stuck_claim'
       when booking_status='booking_unknown' then 'duffel_reconcile' else 'refund_reconcile' end
     from hotel_booking_sessions
     where (booking_status='booking_in_progress' and updated_at < now() - ($1::bigint * interval '1 millisecond'))
        or booking_status in ('booking_unknown','booking_failed_refund_pending')
     on conflict (booking_session_id, kind) do update set
       status='queued', available_at=now(), attempt_count=0, claim_token=null, claimed_by=null,
       claim_expires_at=null, last_error=null, updated_at=now()
     where hotel_booking_recovery_jobs.status='completed'
     returning booking_session_id, kind`, [leaseMs]
  );
  return result.rows;
}

async function claimRecoveryJobs(dbPool, { workerId, limit = 10, leaseMs = 60_000, makeToken = randomUUID } = {}) {
  const client = await dbPool.connect();
  try {
    await client.query("begin");
    const token = makeToken();
    const result = await client.query(
      `with candidates as (
         select booking_session_id, kind from hotel_booking_recovery_jobs
         where (status='queued' and available_at<=now()) or (status='claimed' and claim_expires_at<=now())
         order by available_at, booking_session_id, kind for update skip locked limit $1
       ) update hotel_booking_recovery_jobs jobs set status='claimed', claim_token=$2, claimed_by=$3,
         claim_expires_at=now()+($4::bigint * interval '1 millisecond'), attempt_count=jobs.attempt_count+1, updated_at=now()
       from candidates where jobs.booking_session_id=candidates.booking_session_id and jobs.kind=candidates.kind returning jobs.*`,
      [limit, token, String(workerId || "hotel-recovery-worker"), leaseMs]
    );
    await client.query("commit");
    return result.rows;
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally { client.release(); }
}

async function finishJob(dbPool, job) {
  await dbPool.query(
    `update hotel_booking_recovery_jobs set status='completed', claim_token=null, claimed_by=null,
       claim_expires_at=null, last_error=null, updated_at=now()
     where booking_session_id=$1 and kind=$2 and status='claimed' and claim_token=$3`,
    [job.booking_session_id, job.kind, job.claim_token]
  );
}
async function retryJob(dbPool, job, error, { maximumAttempts = 12 } = {}) {
  const manual = Number(job.attempt_count) >= maximumAttempts;
  const delayMs = retryDelayMs(job.attempt_count);
  await dbPool.query(
    `update hotel_booking_recovery_jobs set status=$4, available_at=now()+($5::bigint * interval '1 millisecond'),
       claim_token=null, claimed_by=null, claim_expires_at=null, last_error=$6, updated_at=now()
     where booking_session_id=$1 and kind=$2 and status='claimed' and claim_token=$3`,
    [job.booking_session_id, job.kind, job.claim_token, manual ? "manual_review" : "queued", delayMs,
      String(error?.message || error || "Hotel recovery failed").slice(0, 500)]
  );
}

function validateReconciledBooking(booking, session) {
  const metadata = booking?.metadata || {};
  return Boolean(booking?.id)
    && String(booking.status || "").toLowerCase() === "confirmed"
    && String(metadata.zippi_booking_session_id || "") === String(session?.id || "")
    && String(metadata.stripe_payment_intent_id || "") === String(session?.stripe_payment_intent_id || "")
    && String(metadata.zippi_duffel_quote_id || "") === String(session?.duffel_quote_id || "")
    && String(metadata.zippi_duffel_rate_id || "") === String(session?.duffel_rate_id || "")
    && String(metadata.zippi_provider_currency || "").toUpperCase() === String(session?.provider_currency || "").toUpperCase()
    && String(metadata.zippi_provider_total_minor || "") === String(session?.provider_total_minor || "")
    && String(metadata.zippi_customer_currency || "").toUpperCase() === customerCurrency(session)
    && String(metadata.zippi_customer_total_minor || "") === String(session?.customer_total_minor || "");
}
function validateRefund(refund, session) {
  const paymentIntent = typeof refund?.payment_intent === "string" ? refund.payment_intent : refund?.payment_intent?.id;
  return Boolean(refund?.id) && refund.status === "succeeded"
    && String(paymentIntent || "") === String(session?.stripe_payment_intent_id || "")
    && String(refund.currency || "").toUpperCase() === customerCurrency(session)
    && Number(refund.amount) === Number(session?.customer_total_minor)
    && String(refund.metadata?.booking_session_id || "") === String(session?.id || "");
}
function buildConfirmation(booking, session) {
  return {
    bookingSessionId: session.id,
    bookingId: booking.id,
    confirmationCode: String(booking.reference || booking.booking_reference || booking.confirmation_number || "").trim() || null,
    status: String(booking.status || "confirmed"),
    hotel: session.hotel_snapshot,
    room: session.room_snapshot,
    search: session.search_snapshot,
    guests: session.guest_info || [],
    currency: session.customer_currency,
    totalMinor: Number(session.customer_total_minor),
    cancellationTimeline: booking.cancellation_timeline || session.quote_snapshot?.cancellation_timeline || [],
  };
}

function createHotelRecoveryService({ dbPool, stripe, duffelLookup, leaseMs = 5 * 60 * 1000, jobOptions = {} }) {
  async function load(id) { return (await dbPool.query("select * from hotel_booking_sessions where id=$1", [id])).rows[0] || null; }
  async function processJob(job) {
    try {
      if (job.kind === "stuck_claim") {
        const result = await recoverStaleBookingClaim(dbPool, { sessionId: job.booking_session_id, leaseMs });
        if (result.disposition === "unchanged" && result.session?.booking_status === "booking_in_progress") throw new Error("Stuck claim is not yet recoverable");
      } else if (job.kind === "duffel_reconcile") {
        const session = await load(job.booking_session_id);
        if (session?.booking_status === "booking_unknown") {
          const lookup = await duffelLookup.findBookingForSession(session);
          if (lookup.status !== "found" || !validateReconciledBooking(lookup.booking, session)) {
            throw new Error("Duffel outcome remains unknown; booking must not be retried or refunded");
          }
          const confirmation = buildConfirmation(lookup.booking, session);
          await dbPool.query(
            `update hotel_booking_sessions set booking_status='confirmed', duffel_booking_id=$2,
             duffel_booking_reference=$3, duffel_request_id=coalesce($4,duffel_request_id), confirmation_snapshot=$5::jsonb,
             recovery_status=null, failure_code=null, failure_message=null, confirmed_at=now(), updated_at=now()
             where id=$1 and booking_status='booking_unknown'`,
            [session.id, lookup.booking.id, confirmation.confirmationCode, lookup.requestId, JSON.stringify(confirmation)]
          );
        }
      } else if (job.kind === "refund_reconcile") {
        const session = await load(job.booking_session_id);
        if (session?.booking_status === "booking_failed_refund_pending") {
          const refund = session.stripe_refund_id
            ? await stripe.refunds.retrieve(session.stripe_refund_id)
            : await stripe.refunds.create({ payment_intent: session.stripe_payment_intent_id, reason: "requested_by_customer",
                metadata: { booking_session_id: session.id, booking_type: "hotel", failure_code: session.failure_code || "booking_failed" } },
              { idempotencyKey: `hotel-refund-${session.id}` });
          if (!validateRefund(refund, session)) throw new Error(`Stripe refund is ${refund.status || "not complete"} or does not match the Hotel charge`);
          await dbPool.query(
            `update hotel_booking_sessions set booking_status='booking_failed_refunded', stripe_refund_id=$2,
             recovery_status='refunded', booking_claim_token=null, booking_claim_expires_at=null, updated_at=now()
             where id=$1 and booking_status='booking_failed_refund_pending'`, [session.id, refund.id]
          );
        }
      } else throw new Error(`Unsupported Hotel recovery job kind: ${job.kind}`);
      await finishJob(dbPool, job);
      return { completed: true };
    } catch (error) {
      await retryJob(dbPool, job, error, jobOptions);
      return { completed: false, error: error.message };
    }
  }
  async function runOnce({ workerId, limit = 1 } = {}) {
    await repairRecoveryJobs(dbPool, { leaseMs });
    const jobs = await claimRecoveryJobs(dbPool, { workerId, limit });
    const results = [];
    for (const job of jobs) results.push(await processJob(job));
    return { claimed: jobs.length, results };
  }
  return { processJob, runOnce };
}

module.exports = {
  JOB_KINDS, buildConfirmation, createHotelRecoveryService, recoverStaleBookingClaim,
  repairRecoveryJobs, retryDelayMs, validateReconciledBooking, validateRefund,
};
