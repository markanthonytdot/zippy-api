const { createHash } = require("crypto");
const { currencyExponent, decimalToMinorExact, minorToDecimal } = require("./currencyAmount");

class HotelBookingError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message);
    this.name = "HotelBookingError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const ACTIVE_STATUSES = [
  "guest_details_required", "payment_setup", "awaiting_payment", "payment_paid",
  "booking_in_progress", "booking_unknown",
];
const DEFINITIVE_DUFFEL_FAILURES = new Set([400, 401, 402, 403, 404, 405, 413, 415, 422]);

function clean(value) { return String(value || "").trim(); }
function currency(value) { return clean(value).toUpperCase(); }
function isUUID(value) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clean(value)); }
function isISODate(value) {
  const raw = clean(value);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) return false;
  const date = new Date(`${raw}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === raw;
}
function factor(code) { return 10 ** currencyExponent(code); }
function minorFromMajorNumber(value, code) {
  const minor = Math.ceil((Number(value) * factor(code)) - 1e-9);
  if (!Number.isSafeInteger(minor) || minor <= 0) {
    throw new HotelBookingError(502, "invalid_price_conversion", "The Hotel price could not be converted safely.");
  }
  return minor;
}
function rateFromExchangeRates(from, to, exchangeRates) {
  if (from === to) return 1;
  const base = currency(exchangeRates?.base);
  const rates = exchangeRates?.rates || {};
  const fromRate = Number(rates[from]);
  const toRate = Number(rates[to]);
  if (from === base && toRate > 0) return toRate;
  if (to === base && fromRate > 0) return 1 / fromRate;
  if (fromRate > 0 && toRate > 0) return toRate / fromRate;
  throw new HotelBookingError(503, "exchange_rate_unavailable", `A ${from} to ${to} exchange rate is not available right now.`);
}
function normalizeQuote(quote, customerCurrency, exchangeRates) {
  const providerCurrency = currency(quote?.total_currency);
  if (!providerCurrency) throw new HotelBookingError(502, "invalid_provider_currency", "Duffel returned an invalid Hotel currency.");
  let providerTotalMinor;
  try {
    providerTotalMinor = decimalToMinorExact(quote?.total_amount, providerCurrency);
  } catch (error) {
    throw new HotelBookingError(502, "invalid_provider_price", error.message);
  }
  if (providerTotalMinor <= 0) throw new HotelBookingError(502, "invalid_provider_price", "Duffel returned an invalid Hotel total.");
  const requestedCurrency = currency(customerCurrency);
  if (!requestedCurrency) throw new HotelBookingError(400, "missing_currency", "A customer currency is required.");
  const fxRate = rateFromExchangeRates(providerCurrency, requestedCurrency, exchangeRates);
  const customerTotalMinor = providerCurrency === requestedCurrency
    ? providerTotalMinor
    : minorFromMajorNumber((providerTotalMinor / factor(providerCurrency)) * fxRate, requestedCurrency);
  return {
    providerCurrency,
    providerTotalMinor,
    customerCurrency: requestedCurrency,
    customerTotalMinor,
    fxRate,
    fxSource: clean(exchangeRates?.source) || (providerCurrency === requestedCurrency ? "same_currency" : "exchange_rates"),
  };
}
function publicQuote(quote, pricing) {
  return {
    quoteId: clean(quote?.id),
    expiresAt: quote?.expires_at || null,
    checkInDate: quote?.check_in_date || null,
    checkOutDate: quote?.check_out_date || null,
    rooms: Number(quote?.rooms || 1),
    currency: pricing.customerCurrency,
    totalMinor: pricing.customerTotalMinor,
    provider: { currency: pricing.providerCurrency, totalMinor: pricing.providerTotalMinor },
    dueAtAccommodation: quote?.due_at_accommodation_amount == null ? null : {
      amount: quote.due_at_accommodation_amount,
      currency: currency(quote.due_at_accommodation_currency || pricing.providerCurrency),
    },
    cancellationTimeline: quote?.cancellation_timeline || [],
  };
}
function normalizeGuest(raw, index) {
  const firstName = clean(raw?.firstName || raw?.given_name);
  const lastName = clean(raw?.lastName || raw?.family_name);
  const bornOn = clean(raw?.dateOfBirthISO || raw?.born_on);
  if (!firstName || !lastName) throw new HotelBookingError(400, "invalid_guest_name", `Guest ${index + 1} needs a first and last name.`);
  if (!isISODate(bornOn)) throw new HotelBookingError(400, "invalid_guest_birth_date", `Guest ${index + 1} needs a valid date of birth.`);
  return { firstName, lastName, dateOfBirthISO: bornOn };
}
function validateGuestPayload(raw) {
  const guests = (Array.isArray(raw?.guests) ? raw.guests : []).map(normalizeGuest);
  if (!guests.length || guests.length > 18) throw new HotelBookingError(400, "invalid_guests", "At least one Hotel guest is required.");
  const email = clean(raw?.contact?.email).toLowerCase();
  const phone = clean(raw?.contact?.phone).replace(/[\s()-]/g, "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HotelBookingError(400, "invalid_contact_email", "A valid contact email is required.");
  if (!/^\+[1-9]\d{6,14}$/.test(phone)) throw new HotelBookingError(400, "invalid_contact_phone", "Enter the phone number in international format, for example +14165551234.");
  return { guests, contact: { email, phone } };
}
function errorInfo(json) {
  const first = Array.isArray(json?.errors) ? json.errors[0] : null;
  return {
    code: clean(first?.code) || "duffel_stay_booking_failed",
    message: clean(first?.message) || "Duffel could not create this Hotel booking.",
    requestId: clean(json?.meta?.request_id) || null,
  };
}
function endpointError(error) {
  if (error instanceof HotelBookingError) {
    return { status: error.status, body: { ok: false, code: error.code, error: error.message, details: error.details } };
  }
  return { status: 500, body: { ok: false, code: "hotel_booking_server_error", error: "Hotel checkout failed unexpectedly." } };
}

function createHotelBookingService(options) {
  const { dbPool, stripe, duffelToken, duffelMode, duffelVersion, fetchWithTimeout, randomUUID,
    enabled, getExchangeRates, bookingTimeoutMs = 130000 } = options;

  function assertConfigured({ database = true } = {}) {
    if (!enabled) throw new HotelBookingError(403, "hotel_test_booking_disabled", "Hotel TEST booking is disabled on this server.");
    if (database && !dbPool) throw new HotelBookingError(500, "database_not_configured", "Hotel checkout database is not configured.");
    if (database && !stripe) throw new HotelBookingError(500, "stripe_test_required", "Stripe TEST mode is not configured.");
    if (duffelMode !== "TEST" || !clean(duffelToken).startsWith("duffel_test_")) {
      throw new HotelBookingError(500, "duffel_test_token_required", "A Duffel Stays TEST token with booking permission is required.");
    }
  }
  async function fetchDuffel(path, request = {}, timeout = 15000) {
    let response;
    try {
      response = await fetchWithTimeout(`https://api.duffel.com${path}`, {
        ...request,
        headers: {
          Accept: "application/json", "Accept-Encoding": "gzip",
          Authorization: `Bearer ${duffelToken}`, "Duffel-Version": duffelVersion,
          ...(request.headers || {}),
        },
      }, timeout);
    } catch (cause) {
      const error = new HotelBookingError(504, "duffel_timeout", "Duffel did not respond in time.");
      error.cause = cause;
      throw error;
    }
    const text = await response.text().catch(() => "");
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (_) { json = null; }
    return { response, json };
  }
  async function fetchQuote(quoteId) {
    const result = await fetchDuffel(`/stays/quotes/${encodeURIComponent(quoteId)}`);
    if (!result.response.ok || !result.json?.data) {
      const info = errorInfo(result.json);
      throw new HotelBookingError([404, 410, 422].includes(result.response.status) ? 409 : 502, info.code, info.message);
    }
    return result.json.data;
  }
  async function createQuote(raw) {
    assertConfigured({ database: false });
    const rateId = clean(raw?.rateId);
    const requestedCurrency = currency(raw?.currency);
    if (!rateId) throw new HotelBookingError(400, "missing_rate", "A Duffel Stays rate is required.");
    if (!requestedCurrency) throw new HotelBookingError(400, "missing_currency", "A customer currency is required.");
    const result = await fetchDuffel("/stays/quotes", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { rate_id: rateId } }),
    });
    if (result.response.status !== 201 || !result.json?.data?.id) {
      const info = errorInfo(result.json);
      throw new HotelBookingError([404, 410, 422].includes(result.response.status) ? 409 : 502, info.code, info.message);
    }
    const exchangeRates = await getExchangeRates?.();
    if (!exchangeRates?.rates) throw new HotelBookingError(503, "exchange_rates_unavailable", "Exchange rates are temporarily unavailable.");
    const pricing = normalizeQuote(result.json.data, requestedCurrency, exchangeRates);
    return { rateId, quote: publicQuote(result.json.data, pricing), rawQuote: result.json.data, pricing };
  }
  async function quoteCheckout(raw) {
    const result = await createQuote(raw);
    return { rateId: result.rateId, quote: result.quote };
  }
  async function createSession(userId, raw) {
    assertConfigured();
    const quoted = raw?.quoteId
      ? await (async () => {
          const quote = await fetchQuote(clean(raw.quoteId));
          const exchangeRates = await getExchangeRates?.();
          if (!exchangeRates?.rates) throw new HotelBookingError(503, "exchange_rates_unavailable", "Exchange rates are temporarily unavailable.");
          return { rateId: clean(raw.rateId), rawQuote: quote, pricing: normalizeQuote(quote, raw.currency, exchangeRates) };
        })()
      : await createQuote(raw);
    if (!quoted.rateId) throw new HotelBookingError(400, "missing_rate", "A Duffel Stays rate is required.");
    const hotel = raw?.hotel && typeof raw.hotel === "object" ? raw.hotel : {};
    const room = raw?.room && typeof raw.room === "object" ? raw.room : {};
    const search = raw?.search && typeof raw.search === "object" ? raw.search : {};
    if (!clean(hotel.id) || !clean(hotel.name) || !isISODate(search.checkIn) || !isISODate(search.checkOut)) {
      throw new HotelBookingError(400, "invalid_hotel_context", "Complete Hotel, room, and trip context is required.");
    }
    const fingerprint = createHash("sha256").update(JSON.stringify({
      userId, quoteId: quoted.rawQuote.id, rateId: quoted.rateId, hotel, room, search,
      providerCurrency: quoted.pricing.providerCurrency, providerTotalMinor: quoted.pricing.providerTotalMinor,
      customerCurrency: quoted.pricing.customerCurrency, customerTotalMinor: quoted.pricing.customerTotalMinor,
    })).digest("hex");
    const client = await dbPool.connect();
    try {
      await client.query("begin");
      await client.query("select pg_advisory_xact_lock(hashtext($1))", [`hotel:${userId}:${fingerprint}`]);
      const existing = await client.query(
        `select * from hotel_booking_sessions where user_id = $1 and checkout_fingerprint = $2
          and booking_status = any($3::text[]) order by created_at desc limit 1 for update`,
        [userId, fingerprint, ACTIVE_STATUSES]
      );
      let session = existing.rows[0];
      if (!session) {
        const id = randomUUID();
        const inserted = await client.query(
          `insert into hotel_booking_sessions (
             id, user_id, checkout_fingerprint, duffel_rate_id, duffel_quote_id,
             quote_snapshot, hotel_snapshot, room_snapshot, search_snapshot,
             provider_currency, provider_total_minor, customer_currency, customer_total_minor,
             fx_rate, fx_source
           ) values ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14,$15)
           returning *`,
          [id, userId, fingerprint, quoted.rateId, quoted.rawQuote.id, JSON.stringify(quoted.rawQuote),
            JSON.stringify(hotel), JSON.stringify(room), JSON.stringify(search), quoted.pricing.providerCurrency,
            quoted.pricing.providerTotalMinor, quoted.pricing.customerCurrency, quoted.pricing.customerTotalMinor,
            quoted.pricing.fxRate, quoted.pricing.fxSource]
        );
        session = inserted.rows[0];
      }
      await client.query("commit");
      return { bookingSessionId: session.id, status: session.booking_status, quote: publicQuote(session.quote_snapshot, {
        providerCurrency: session.provider_currency, providerTotalMinor: Number(session.provider_total_minor),
        customerCurrency: session.customer_currency, customerTotalMinor: Number(session.customer_total_minor),
      }) };
    } catch (error) {
      await client.query("rollback").catch(() => {});
      throw error;
    } finally { client.release(); }
  }
  async function saveGuests(userId, sessionId, raw) {
    assertConfigured();
    if (!isUUID(sessionId)) throw new HotelBookingError(400, "invalid_booking_session", "The booking session ID is invalid.");
    const normalized = validateGuestPayload(raw);
    const current = await dbPool.query(
      "select search_snapshot from hotel_booking_sessions where id = $1 and user_id = $2",
      [sessionId, userId]
    );
    if (!current.rows[0]) throw new HotelBookingError(404, "booking_session_not_found", "Hotel booking session not found.");
    const expectedGuests = Number(current.rows[0].search_snapshot?.adults || 0);
    if (Number.isSafeInteger(expectedGuests) && expectedGuests > 0 && normalized.guests.length !== expectedGuests) {
      throw new HotelBookingError(409, "guest_count_changed", `This Hotel rate requires details for ${expectedGuests} guest${expectedGuests === 1 ? "" : "s"}.`);
    }
    const updated = await dbPool.query(
      `update hotel_booking_sessions set guest_info = $3::jsonb, contact_info = $4::jsonb,
         booking_status = case when booking_status = 'guest_details_required' then 'payment_setup' else booking_status end,
         updated_at = now()
       where id = $1 and user_id = $2 and booking_status in ('guest_details_required','payment_setup','awaiting_payment') returning *`,
      [sessionId, userId, JSON.stringify(normalized.guests), JSON.stringify(normalized.contact)]
    );
    if (!updated.rows[0]) throw new HotelBookingError(409, "booking_session_advanced", "This Hotel booking session can no longer accept guest changes.");
    return statusResponse(updated.rows[0]);
  }
  async function paymentSetup(userId, sessionId) {
    assertConfigured();
    if (!isUUID(sessionId)) throw new HotelBookingError(400, "invalid_booking_session", "The booking session ID is invalid.");
    let result = await dbPool.query("select * from hotel_booking_sessions where id = $1 and user_id = $2", [sessionId, userId]);
    let session = result.rows[0];
    if (!session) throw new HotelBookingError(404, "booking_session_not_found", "Hotel booking session not found.");
    if (!Array.isArray(session.guest_info) || !session.guest_info.length || !session.contact_info?.email) {
      throw new HotelBookingError(409, "guest_details_required", "Guest and contact details are required before payment.");
    }
    if (!["payment_setup", "awaiting_payment"].includes(session.booking_status)) {
      throw new HotelBookingError(409, "booking_session_advanced", "This Hotel booking session already advanced.");
    }
    let intent = session.stripe_payment_intent_id
      ? await stripe.paymentIntents.retrieve(session.stripe_payment_intent_id)
      : null;
    if (intent?.status === "canceled") {
      await dbPool.query("update hotel_booking_sessions set booking_status = 'payment_canceled', stripe_payment_status = $3, updated_at = now() where id = $1 and user_id = $2", [sessionId, userId, intent.status]);
      throw new HotelBookingError(409, "payment_canceled", "This payment session was canceled. Start Hotel checkout again.");
    }
    if (!intent) {
      intent = await stripe.paymentIntents.create({
        amount: Number(session.customer_total_minor), currency: session.customer_currency.toLowerCase(),
        payment_method_types: ["card"], receipt_email: session.contact_info.email,
        description: `Zippi TEST Hotel ${clean(session.hotel_snapshot?.name)}`,
        metadata: { booking_session_id: session.id, booking_type: "hotel", duffel_quote_id: session.duffel_quote_id, environment: "test" },
      }, { idempotencyKey: `hotel-payment-${session.id}` });
    }
    if (intent.amount !== Number(session.customer_total_minor) || currency(intent.currency) !== session.customer_currency) {
      throw new HotelBookingError(409, "payment_amount_changed", "The existing Hotel payment session has a different total.");
    }
    if (!intent.client_secret) throw new HotelBookingError(502, "stripe_setup_failed", "Stripe did not return a payment client secret.");
    result = await dbPool.query(
      `update hotel_booking_sessions set stripe_payment_intent_id = $3, stripe_payment_status = $4,
        booking_status = 'awaiting_payment', updated_at = now()
       where id = $1 and user_id = $2 and booking_status in ('payment_setup','awaiting_payment') returning *`,
      [sessionId, userId, intent.id, intent.status]
    );
    if (!result.rows[0]) throw new HotelBookingError(409, "booking_session_advanced", "This Hotel booking session already advanced.");
    session = result.rows[0];
    return { paymentIntentClientSecret: intent.client_secret, ...statusResponse(session) };
  }
  function statusResponse(session) {
    return {
      bookingSessionId: session.id, status: session.booking_status,
      paymentStatus: session.stripe_payment_status, recoveryStatus: session.recovery_status || null,
      failure: session.failure_code ? { code: session.failure_code, message: session.failure_message || null } : null,
      quote: publicQuote(session.quote_snapshot, {
        providerCurrency: session.provider_currency, providerTotalMinor: Number(session.provider_total_minor),
        customerCurrency: session.customer_currency, customerTotalMinor: Number(session.customer_total_minor),
      }),
      hotel: session.hotel_snapshot, room: session.room_snapshot, search: session.search_snapshot,
      guests: session.guest_info || [], contact: session.contact_info || null,
      confirmation: session.confirmation_snapshot || null, updatedAt: session.updated_at || null,
    };
  }
  async function getStatus(userId, sessionId) {
    assertConfigured();
    if (!isUUID(sessionId)) throw new HotelBookingError(400, "invalid_booking_session", "The booking session ID is invalid.");
    let result = await dbPool.query("select * from hotel_booking_sessions where id = $1 and user_id = $2", [sessionId, userId]);
    let session = result.rows[0];
    if (!session) throw new HotelBookingError(404, "booking_session_not_found", "Hotel booking session not found.");
    if (session.stripe_payment_intent_id && ["payment_setup", "awaiting_payment", "payment_paid"].includes(session.booking_status)) {
      const intent = await stripe.paymentIntents.retrieve(session.stripe_payment_intent_id);
      const matches = intent.amount === Number(session.customer_total_minor) && currency(intent.currency) === session.customer_currency;
      if (intent.status === "succeeded" && !matches) throw new HotelBookingError(409, "stripe_amount_mismatch", "The completed payment does not match this Hotel booking.");
      const next = intent.status === "succeeded" ? "payment_paid" : session.booking_status;
      result = await dbPool.query(
        `update hotel_booking_sessions set stripe_payment_status = $3, booking_status = $4, updated_at = now()
         where id = $1 and user_id = $2 and booking_status in ('payment_setup','awaiting_payment','payment_paid') returning *`,
        [sessionId, userId, intent.status, next]
      );
      session = result.rows[0] || session;
    }
    return statusResponse(session);
  }
  async function refundDefinitive(session, code, message, requestId) {
    await dbPool.query(
      `update hotel_booking_sessions set booking_status='booking_failed_refund_pending', recovery_status='refund_started',
       failure_code=$2, failure_message=$3, duffel_request_id=coalesce($4,duffel_request_id), updated_at=now() where id=$1`,
      [session.id, code, message, requestId]
    );
    try {
      const refund = await stripe.refunds.create({ payment_intent: session.stripe_payment_intent_id,
        reason: "requested_by_customer", metadata: { booking_session_id: session.id, booking_type: "hotel", failure_code: code } },
      { idempotencyKey: `hotel-refund-${session.id}` });
      const completed = refund.status === "succeeded";
      await dbPool.query(
        `update hotel_booking_sessions set booking_status=$2, recovery_status=$3, stripe_refund_id=$4,
         booking_claim_token=null, booking_claim_expires_at=null, updated_at=now() where id=$1`,
        [session.id, completed ? "booking_failed_refunded" : "booking_failed_refund_pending", completed ? "refunded" : "refund_pending", refund.id]
      );
    } catch (_) {
      await dbPool.query("update hotel_booking_sessions set recovery_status='refund_failed', updated_at=now() where id=$1", [session.id]);
    }
  }
  async function confirm(userId, sessionId) {
    assertConfigured();
    if (!isUUID(sessionId)) throw new HotelBookingError(400, "invalid_booking_session", "The booking session ID is invalid.");
    const claimToken = randomUUID();
    let claimed = await dbPool.query(
      `update hotel_booking_sessions set booking_status='booking_in_progress', booking_claim_token=$3,
       booking_claim_expires_at=now()+interval '5 minutes', updated_at=now()
       where id=$1 and user_id=$2 and booking_status='payment_paid' and duffel_post_started_at is null returning *`,
      [sessionId, userId, claimToken]
    );
    if (!claimed.rows[0]) {
      const current = await dbPool.query("select * from hotel_booking_sessions where id=$1 and user_id=$2", [sessionId, userId]);
      const session = current.rows[0];
      if (!session) throw new HotelBookingError(404, "booking_session_not_found", "Hotel booking session not found.");
      if (session.booking_status === "confirmed") return session.confirmation_snapshot;
      if (session.booking_status === "booking_unknown" || session.duffel_post_started_at) {
        throw new HotelBookingError(409, "booking_outcome_unknown", "The Hotel booking outcome is being reconciled. Do not retry or submit another payment.");
      }
      if (["payment_setup", "awaiting_payment"].includes(session.booking_status)) {
        const refreshed = await getStatus(userId, sessionId);
        if (refreshed.status === "payment_paid") return confirm(userId, sessionId);
        throw new HotelBookingError(402, "payment_not_completed", "Stripe payment has not completed.");
      }
      throw new HotelBookingError(409, "booking_session_advanced", "This Hotel booking cannot be confirmed from its current state.");
    }
    let session = claimed.rows[0];
    let intent;
    try { intent = await stripe.paymentIntents.retrieve(session.stripe_payment_intent_id); }
    catch (_) {
      await dbPool.query("update hotel_booking_sessions set booking_status='payment_paid', booking_claim_token=null, booking_claim_expires_at=null, updated_at=now() where id=$1 and booking_claim_token=$2", [session.id, claimToken]);
      throw new HotelBookingError(502, "stripe_verification_failed", "Payment verification is temporarily unavailable.");
    }
    if (intent.status !== "succeeded" || intent.amount !== Number(session.customer_total_minor) || currency(intent.currency) !== session.customer_currency) {
      await dbPool.query("update hotel_booking_sessions set booking_status='awaiting_payment', booking_claim_token=null, booking_claim_expires_at=null, updated_at=now() where id=$1 and booking_claim_token=$2", [session.id, claimToken]);
      throw new HotelBookingError(402, "payment_not_completed", "Stripe payment has not completed.");
    }
    let freshQuote;
    try {
      freshQuote = await fetchQuote(session.duffel_quote_id);
    } catch (error) {
      if (error instanceof HotelBookingError && error.status === 409) {
        await refundDefinitive(session, error.code || "hotel_rate_unavailable", error.message, null);
        throw new HotelBookingError(409, "hotel_rate_unavailable", "The Hotel rate is no longer available. Payment refund recovery has started.");
      }
      await dbPool.query(
        `update hotel_booking_sessions set booking_status='payment_paid', recovery_status='safe_retry_ready',
         failure_code='quote_verification_unavailable', failure_message='Duffel quote verification is temporarily unavailable.',
         booking_claim_token=null, booking_claim_expires_at=null, updated_at=now()
         where id=$1 and booking_claim_token=$2 and duffel_post_started_at is null`,
        [session.id, claimToken]
      );
      throw new HotelBookingError(502, "quote_verification_unavailable", "The Hotel rate could not be verified right now. It is safe to check again; no Duffel booking was submitted.");
    }
    const freshProviderTotal = decimalToMinorExact(freshQuote.total_amount, currency(freshQuote.total_currency));
    if (currency(freshQuote.total_currency) !== session.provider_currency || freshProviderTotal !== Number(session.provider_total_minor)) {
      await refundDefinitive(session, "hotel_price_changed", "The Hotel price changed before booking.", null);
      throw new HotelBookingError(409, "hotel_price_changed", "The Hotel price changed before booking. Payment refund recovery has started.");
    }
    const marked = await dbPool.query(
      "update hotel_booking_sessions set duffel_post_started_at=now(), updated_at=now() where id=$1 and booking_claim_token=$2 and duffel_post_started_at is null returning *",
      [session.id, claimToken]
    );
    if (!marked.rows[0]) throw new HotelBookingError(409, "booking_outcome_unknown", "The Hotel booking outcome requires reconciliation.");
    const data = {
      quote_id: session.duffel_quote_id, email: session.contact_info.email, phone_number: session.contact_info.phone,
      guests: session.guest_info.map((guest) => ({ given_name: guest.firstName, family_name: guest.lastName, born_on: guest.dateOfBirthISO })),
      metadata: {
        zippi_booking_session_id: session.id,
        stripe_payment_intent_id: session.stripe_payment_intent_id,
        zippi_duffel_quote_id: session.duffel_quote_id,
        zippi_duffel_rate_id: session.duffel_rate_id,
        zippi_provider_currency: session.provider_currency,
        zippi_provider_total_minor: String(session.provider_total_minor),
        zippi_customer_currency: session.customer_currency,
        zippi_customer_total_minor: String(session.customer_total_minor),
      },
    };
    let result;
    try {
      result = await fetchDuffel("/stays/bookings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ data }) }, bookingTimeoutMs);
    } catch (_) {
      await dbPool.query(
        `update hotel_booking_sessions set booking_status='booking_unknown', recovery_status='manual_reconciliation_required',
         failure_code='duffel_timeout', failure_message='Duffel booking timed out; outcome requires reconciliation.',
         booking_claim_token=null, booking_claim_expires_at=null, updated_at=now() where id=$1 and booking_claim_token=$2`, [session.id, claimToken]
      );
      throw new HotelBookingError(504, "booking_outcome_unknown", "The Hotel booking outcome is being reconciled. Do not retry or submit another payment.");
    }
    if (result.response.status === 201 && result.json?.data?.id) {
      const booking = result.json.data;
      const confirmation = {
        bookingSessionId: session.id, bookingId: booking.id,
        confirmationCode: clean(booking.reference || booking.booking_reference || booking.confirmation_number) || null,
        status: clean(booking.status) || "confirmed", hotel: session.hotel_snapshot, room: session.room_snapshot,
        search: session.search_snapshot, guests: session.guest_info,
        currency: session.customer_currency, totalMinor: Number(session.customer_total_minor),
        cancellationTimeline: booking.cancellation_timeline || session.quote_snapshot?.cancellation_timeline || [],
      };
      const saved = await dbPool.query(
        `update hotel_booking_sessions set booking_status='confirmed', stripe_payment_status='succeeded',
         duffel_booking_id=$3, duffel_booking_reference=$4, duffel_request_id=$5,
         confirmation_snapshot=$6::jsonb, confirmed_at=now(), recovery_status=null, failure_code=null,
         failure_message=null, booking_claim_token=null, booking_claim_expires_at=null, updated_at=now()
         where id=$1 and booking_claim_token=$2 and booking_status='booking_in_progress' returning *`,
        [session.id, claimToken, booking.id, confirmation.confirmationCode, clean(result.json?.meta?.request_id) || null, JSON.stringify(confirmation)]
      );
      if (!saved.rows[0]) throw new HotelBookingError(409, "booking_outcome_unknown", "The confirmed Hotel booking requires reconciliation before it can be shown.");
      return confirmation;
    }
    const info = errorInfo(result.json);
    if (DEFINITIVE_DUFFEL_FAILURES.has(Number(result.response.status))) {
      await refundDefinitive(session, info.code, info.message, info.requestId);
      throw new HotelBookingError(409, info.code, `${info.message} Payment refund recovery has started.`);
    }
    await dbPool.query(
      `update hotel_booking_sessions set booking_status='booking_unknown', recovery_status='manual_reconciliation_required',
       failure_code=$3, failure_message=$4, duffel_request_id=$5, booking_claim_token=null,
       booking_claim_expires_at=null, updated_at=now() where id=$1 and booking_claim_token=$2`,
      [session.id, claimToken, info.code, info.message, info.requestId]
    );
    throw new HotelBookingError(502, "booking_outcome_unknown", "The Hotel booking outcome is being reconciled. Do not retry or submit another payment.");
  }

  return { quoteCheckout, createSession, saveGuests, paymentSetup, getStatus, confirm };
}

module.exports = { HotelBookingError, createHotelBookingService, endpointError, normalizeQuote, publicQuote, validateGuestPayload };
