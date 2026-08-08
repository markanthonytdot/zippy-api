const { createHash } = require("crypto");

class FlightBookingError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message);
    this.name = "FlightBookingError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const ACTIVE_SETUP_STATUSES = [
  "payment_setup",
  "awaiting_payment",
  "payment_paid",
  "booking_in_progress",
  "booking_unknown",
];

const ZERO_DECIMAL_CURRENCIES = new Set([
  "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
]);
const THREE_DECIMAL_CURRENCIES = new Set(["BHD", "JOD", "KWD", "OMR", "TND"]);

function currencyExponent(currency) {
  const code = String(currency || "").trim().toUpperCase();
  if (ZERO_DECIMAL_CURRENCIES.has(code)) return 0;
  if (THREE_DECIMAL_CURRENCIES.has(code)) return 3;
  return 2;
}

function decimalToMinor(value, currency) {
  const raw = String(value ?? "").trim();
  const match = raw.match(/^(\d+)(?:\.(\d+))?$/);
  if (!match) throw new FlightBookingError(502, "invalid_provider_price", "Duffel returned an invalid price.");

  const exponent = currencyExponent(currency);
  const fractional = match[2] || "";
  if (fractional.length > exponent && /[1-9]/.test(fractional.slice(exponent))) {
    throw new FlightBookingError(502, "invalid_provider_price", "Duffel returned a price with unsupported precision.");
  }

  const digits = `${match[1]}${fractional.slice(0, exponent).padEnd(exponent, "0")}`;
  const minor = Number(BigInt(digits || "0"));
  if (!Number.isSafeInteger(minor)) {
    throw new FlightBookingError(502, "invalid_provider_price", "Duffel returned a price that is too large.");
  }
  return minor;
}

function minorToDecimal(value, currency) {
  const minor = Number(value);
  const exponent = currencyExponent(currency);
  if (!Number.isSafeInteger(minor) || minor < 0) throw new Error("Invalid minor amount");
  if (exponent === 0) return String(minor);
  const raw = String(minor).padStart(exponent + 1, "0");
  return `${raw.slice(0, -exponent)}.${raw.slice(-exponent)}`;
}

function normalizeString(value) {
  return String(value || "").trim();
}

function normalizeCurrency(value) {
  return normalizeString(value).toUpperCase();
}

function isUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(normalizeString(value));
}

function normalizeTitle(value) {
  const title = normalizeString(value).toLowerCase().replace(/\.$/, "");
  const allowed = new Set(["mr", "mrs", "ms", "miss", "dr"]);
  return allowed.has(title) ? title : "";
}

function normalizeGender(value) {
  const gender = normalizeString(value).toLowerCase();
  if (gender === "male" || gender === "m") return "m";
  if (gender === "female" || gender === "f") return "f";
  return "";
}

function isISODate(value) {
  const raw = normalizeString(value);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) return false;
  const parsed = new Date(`${raw}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === raw;
}

function validateCheckoutPayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new FlightBookingError(400, "invalid_request", "Invalid checkout payload.");
  }

  const offerId = normalizeString(payload.offerId);
  if (!offerId) throw new FlightBookingError(400, "missing_offer", "A Duffel offer is required.");
  if (normalizeString(payload.bookingSessionId) && !isUUID(payload.bookingSessionId)) {
    throw new FlightBookingError(400, "invalid_booking_session", "The booking session ID is invalid.");
  }
  if (normalizeString(payload.returnOfferId)) {
    throw new FlightBookingError(422, "one_way_only", "Test checkout currently supports one-way flights only.");
  }

  const travelers = Array.isArray(payload.travelers) ? payload.travelers : [];
  if (!travelers.length || travelers.length > 9) {
    throw new FlightBookingError(400, "invalid_travelers", "Between 1 and 9 travelers are required.");
  }

  travelers.forEach((traveler, index) => {
    if (!normalizeTitle(traveler?.title)) {
      throw new FlightBookingError(400, "invalid_traveler_title", `Traveler ${index + 1} needs a supported title.`);
    }
    if (!normalizeString(traveler?.firstName) || !normalizeString(traveler?.lastName)) {
      throw new FlightBookingError(400, "invalid_traveler_name", `Traveler ${index + 1} needs a first and last name.`);
    }
    if (!isISODate(traveler?.dateOfBirthISO)) {
      throw new FlightBookingError(400, "invalid_traveler_birth_date", `Traveler ${index + 1} needs a valid date of birth.`);
    }
    if (!normalizeGender(traveler?.gender)) {
      throw new FlightBookingError(400, "invalid_traveler_gender", `Traveler ${index + 1} needs Male or Female for this test flow.`);
    }
  });

  const email = normalizeString(payload.contact?.email).toLowerCase();
  const phone = normalizeString(payload.contact?.phone).replace(/[\s()-]/g, "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new FlightBookingError(400, "invalid_contact_email", "A valid contact email is required.");
  }
  if (!/^\+[1-9]\d{6,14}$/.test(phone)) {
    throw new FlightBookingError(400, "invalid_contact_phone", "Enter the contact phone in international format, for example +14165551234.");
  }

  const clientTotalMinor = Number(payload.totalMinor);
  if (!Number.isSafeInteger(clientTotalMinor) || clientTotalMinor <= 0) {
    throw new FlightBookingError(400, "invalid_total", "A valid checkout total is required.");
  }

  return {
    ...payload,
    offerId,
    travelers,
    contact: { email, phone },
    currency: normalizeCurrency(payload.currency),
    totalMinor: clientTotalMinor,
  };
}

function assertFreshOneWayOffer(offer) {
  if (!offer?.id) throw new FlightBookingError(502, "invalid_offer", "Duffel returned an invalid offer.");
  const slices = Array.isArray(offer.slices) ? offer.slices : [];
  if (slices.length !== 1) {
    throw new FlightBookingError(422, "one_way_only", "Test checkout currently supports a single one-way Duffel offer only.");
  }
  const expiresAt = normalizeString(offer.expires_at);
  if (expiresAt) {
    const expiresMs = Date.parse(expiresAt);
    if (Number.isFinite(expiresMs) && expiresMs <= Date.now()) {
      throw new FlightBookingError(409, "offer_expired", "This fare has expired. Search again for a current offer.");
    }
  }
}

function requestedServiceQuantities(payload) {
  const quantities = new Map();
  const add = (id) => {
    const clean = normalizeString(id);
    if (clean) quantities.set(clean, (quantities.get(clean) || 0) + 1);
  };
  (Array.isArray(payload.baggageServiceIds) ? payload.baggageServiceIds : []).forEach(add);
  add(payload.seatServiceId);
  add(payload.cfarServiceId);
  return quantities;
}

function collectRequestedServiceRecords(node, requestedIds, records, seen = new Set()) {
  if (!node || typeof node !== "object" || seen.has(node)) return;
  seen.add(node);
  if (!Array.isArray(node)) {
    const id = normalizeString(node.id);
    if (requestedIds.has(id) && node.total_amount != null && node.total_currency != null) {
      records.set(id, node);
    }
  }
  for (const value of Object.values(node)) {
    if (value && typeof value === "object") collectRequestedServiceRecords(value, requestedIds, records, seen);
  }
}

function resolveSelectedServices(payload, offer, seatMaps) {
  const quantities = requestedServiceQuantities(payload);
  if (!quantities.size) return [];

  const requestedIds = new Set(quantities.keys());
  const records = new Map();
  collectRequestedServiceRecords(offer?.available_services || [], requestedIds, records);
  collectRequestedServiceRecords(seatMaps || [], requestedIds, records);

  return [...quantities.entries()].map(([id, quantity]) => {
    const service = records.get(id);
    if (!service) {
      throw new FlightBookingError(409, "service_unavailable", "A selected seat, bag, or extra is no longer available.", { serviceId: id });
    }
    const currency = normalizeCurrency(service.total_currency);
    const maximumQuantity = Number(service.maximum_quantity ?? 1);
    if (!Number.isInteger(maximumQuantity) || quantity > maximumQuantity) {
      throw new FlightBookingError(409, "service_quantity_unavailable", "The selected quantity for an extra is no longer available.", { serviceId: id });
    }
    const unitMinor = decimalToMinor(service.total_amount, currency);
    return { id, quantity, currency, unitMinor, totalMinor: unitMinor * quantity };
  });
}

function calculatePricing(offer, services, zippiFeeMinor) {
  const currency = normalizeCurrency(offer?.total_currency);
  if (!currency) throw new FlightBookingError(502, "invalid_offer_currency", "Duffel returned an invalid offer currency.");
  const offerMinor = decimalToMinor(offer?.total_amount, currency);
  let servicesMinor = 0;
  for (const service of services) {
    if (service.currency !== currency) {
      throw new FlightBookingError(409, "service_currency_mismatch", "A selected extra uses a different currency.");
    }
    servicesMinor += service.totalMinor;
  }
  const duffelTotalMinor = offerMinor + servicesMinor;
  return {
    currency,
    offerMinor,
    servicesMinor,
    duffelTotalMinor,
    zippiFeeMinor,
    chargeTotalMinor: duffelTotalMinor + zippiFeeMinor,
  };
}

function buildDuffelPassengers(travelers, contact, offerPassengers) {
  if (!Array.isArray(offerPassengers) || offerPassengers.length !== travelers.length) {
    throw new FlightBookingError(409, "passenger_count_changed", "The traveler count no longer matches this fare.");
  }

  return travelers.map((traveler, index) => {
    const firstName = normalizeString(traveler.firstName);
    const middleName = normalizeString(traveler.middleName);
    const passenger = {
      id: normalizeString(offerPassengers[index]?.id),
      title: normalizeTitle(traveler.title),
      given_name: middleName ? `${firstName} ${middleName}` : firstName,
      family_name: normalizeString(traveler.lastName),
      born_on: normalizeString(traveler.dateOfBirthISO),
      gender: normalizeGender(traveler.gender),
      email: contact.email,
      phone_number: contact.phone,
    };
    if (!passenger.id) throw new FlightBookingError(502, "missing_passenger_id", "Duffel did not return a passenger reference.");

    const passportNumber = normalizeString(traveler.passportNumber);
    const passportCountry = normalizeString(traveler.passportCountry).toUpperCase();
    const passportExpiry = normalizeString(traveler.passportExpiryISO);
    if (passportNumber || passportCountry || passportExpiry) {
      if (!passportNumber || !/^[A-Z]{2}$/.test(passportCountry) || !isISODate(passportExpiry)) {
        throw new FlightBookingError(400, "invalid_passport", `Traveler ${index + 1} has incomplete passport details.`);
      }
      passenger.identity_documents = [{
        type: "passport",
        unique_identifier: passportNumber,
        issuing_country_code: passportCountry,
        expires_on: passportExpiry,
      }];
    }
    return passenger;
  });
}

function checkoutFingerprint(userId, payload, offer, services, pricing) {
  const fingerprintPayload = {
    userId,
    offerId: payload.offerId,
    offerExpiresAt: offer.expires_at || null,
    travelers: payload.travelers,
    contact: payload.contact,
    services: services.map(({ id, quantity }) => ({ id, quantity })),
    currency: pricing.currency,
    totalMinor: pricing.chargeTotalMinor,
  };
  return createHash("sha256").update(JSON.stringify(fingerprintPayload)).digest("hex");
}

function summarizeOffer(offer) {
  return {
    id: offer.id,
    expiresAt: offer.expires_at || null,
    totalAmount: offer.total_amount,
    totalCurrency: offer.total_currency,
    slices: offer.slices || [],
    owner: offer.owner || null,
    paymentRequirements: offer.payment_requirements || null,
  };
}

function duffelErrorInfo(json) {
  const first = Array.isArray(json?.errors) ? json.errors[0] : null;
  return {
    code: normalizeString(first?.code) || "duffel_order_failed",
    message: normalizeString(first?.message) || "Duffel could not create this booking.",
    requestId: normalizeString(json?.meta?.request_id) || null,
  };
}

function isDefinitiveDuffelOrderFailureStatus(status) {
  const code = Number(status);
  return (code >= 400 && code < 500) || code === 503;
}

function endpointError(error) {
  if (error instanceof FlightBookingError) {
    return { status: error.status, body: { ok: false, code: error.code, error: error.message, details: error.details } };
  }
  return { status: 500, body: { ok: false, code: "booking_server_error", error: "Flight checkout failed unexpectedly." } };
}

function buildConfirmation(order, session) {
  const slices = Array.isArray(order?.slices) ? order.slices : [];
  const itinerary = slices.map((slice) => {
    const segments = Array.isArray(slice?.segments) ? slice.segments : [];
    const first = segments[0] || {};
    const last = segments[segments.length - 1] || {};
    return {
      origin: normalizeString(first?.origin?.iata_code || first?.origin?.name),
      destination: normalizeString(last?.destination?.iata_code || last?.destination?.name),
      departingAt: normalizeString(first?.departing_at),
      arrivingAt: normalizeString(last?.arriving_at),
      flightNumbers: segments.map((segment) => normalizeString(segment?.marketing_carrier_flight_number || segment?.operating_carrier_flight_number)).filter(Boolean),
    };
  });
  const travelers = (Array.isArray(order?.passengers) ? order.passengers : []).map((passenger) =>
    [passenger.given_name, passenger.family_name].map(normalizeString).filter(Boolean).join(" ")
  ).filter(Boolean);

  return {
    orderId: normalizeString(order?.id),
    confirmationCode: normalizeString(order?.booking_reference) || null,
    currency: session.currency,
    totalMinor: Number(session.charge_total_minor),
    bookingSessionId: session.id,
    airline: normalizeString(order?.owner?.name) || null,
    itinerary,
    travelers,
  };
}

function createFlightBookingService(options) {
  const {
    dbPool,
    stripe,
    duffelToken,
    duffelMode,
    duffelVersion,
    fetchWithTimeout,
    randomUUID,
    enabled,
    zippiFeeMinor = 299,
    orderTimeoutMs = 130000,
  } = options;

  function assertConfigured() {
    if (!enabled) throw new FlightBookingError(403, "test_booking_disabled", "Flight test booking is disabled on this server.");
    if (!dbPool) throw new FlightBookingError(500, "database_not_configured", "Flight checkout database is not configured.");
    if (!stripe) throw new FlightBookingError(500, "stripe_not_configured", "Stripe test mode is not configured.");
    if (duffelMode !== "TEST" || !normalizeString(duffelToken).startsWith("duffel_test_")) {
      throw new FlightBookingError(500, "duffel_test_token_required", "A Duffel test token with booking permission is required.");
    }
  }

  async function fetchDuffel(path, fetchOptions = {}, timeoutMs = 15000) {
    let response;
    try {
      response = await fetchWithTimeout(`https://api.duffel.com${path}`, {
        ...fetchOptions,
        headers: {
          Accept: "application/json",
          "Accept-Encoding": "gzip",
          Authorization: `Bearer ${duffelToken}`,
          "Duffel-Version": duffelVersion,
          ...(fetchOptions.headers || {}),
        },
      }, timeoutMs);
    } catch (error) {
      const wrapped = new FlightBookingError(504, "duffel_timeout", "Duffel did not respond in time.");
      wrapped.cause = error;
      throw wrapped;
    }
    const text = await response.text().catch(() => "");
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch (_) {
      json = null;
    }
    return { response, json };
  }

  async function fetchOffer(offerId) {
    const result = await fetchDuffel(`/air/offers/${encodeURIComponent(offerId)}?return_available_services=true`);
    if (!result.response.ok || !result.json?.data) {
      const info = duffelErrorInfo(result.json);
      const status = result.response.status === 404 || result.response.status === 410 || result.response.status === 422 ? 409 : 502;
      throw new FlightBookingError(status, info.code, info.message);
    }
    return result.json.data;
  }

  async function fetchSeatMaps(offerId) {
    const result = await fetchDuffel(`/air/seat_maps?offer_id=${encodeURIComponent(offerId)}`);
    if (!result.response.ok) return [];
    return result.json?.data || [];
  }

  async function priceCheckout(payload, offer) {
    const quantities = requestedServiceQuantities(payload);
    let services = [];
    try {
      services = resolveSelectedServices(payload, offer, []);
    } catch (error) {
      if (error.code !== "service_unavailable" || !quantities.size) throw error;
      const seatMaps = await fetchSeatMaps(payload.offerId);
      services = resolveSelectedServices(payload, offer, seatMaps);
    }
    const pricing = calculatePricing(offer, services, zippiFeeMinor);
    return { services, pricing };
  }

  async function findOrCreateSession(userId, payload, offer, services, pricing, fingerprint) {
    const suppliedSessionId = normalizeString(payload.bookingSessionId);
    const client = await dbPool.connect();
    try {
      await client.query("begin");
      await client.query("select pg_advisory_xact_lock(hashtext($1))", [`flight:${userId}:${fingerprint}`]);

      let existing = null;
      if (suppliedSessionId) {
        const result = await client.query(
          "select * from flight_booking_sessions where id = $1 and user_id = $2 for update",
          [suppliedSessionId, userId]
        );
        existing = result.rows[0] || null;
        if (!existing) throw new FlightBookingError(404, "booking_session_not_found", "Booking session not found.");
        if (existing.checkout_fingerprint !== fingerprint) {
          throw new FlightBookingError(409, "booking_session_changed", "Checkout details changed. Start payment again.");
        }
      } else {
        const result = await client.query(
          `select * from flight_booking_sessions
             where user_id = $1 and checkout_fingerprint = $2 and booking_status = any($3::text[])
             order by created_at desc limit 1 for update`,
          [userId, fingerprint, ACTIVE_SETUP_STATUSES]
        );
        existing = result.rows[0] || null;
      }

      if (existing) {
        if (existing.booking_status === "booking_unknown") {
          throw new FlightBookingError(409, "booking_outcome_unknown", "The airline booking outcome is still being reconciled. Do not start another payment.");
        }
        if (["booking_in_progress", "payment_paid"].includes(existing.booking_status)) {
          throw new FlightBookingError(409, "booking_already_processing", "This paid booking is already being processed.");
        }
        if (!["payment_setup", "awaiting_payment"].includes(existing.booking_status)) {
          throw new FlightBookingError(409, "booking_not_payable", "This booking session cannot accept another payment.");
        }
        await client.query("commit");
        return existing;
      }

      const id = randomUUID();
      const result = await client.query(
        `insert into flight_booking_sessions (
           id, user_id, checkout_fingerprint, duffel_offer_id, offer_snapshot, payload_snapshot,
           traveler_info, contact_info, selected_services, currency, offer_minor, services_minor,
           duffel_total_minor, zippi_fee_minor, charge_total_minor, stripe_payment_status, booking_status
         ) values ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14,$15,'not_created','payment_setup')
         returning *`,
        [
          id, userId, fingerprint, payload.offerId, JSON.stringify(summarizeOffer(offer)), JSON.stringify(payload),
          JSON.stringify(payload.travelers), JSON.stringify(payload.contact), JSON.stringify(services), pricing.currency,
          pricing.offerMinor, pricing.servicesMinor, pricing.duffelTotalMinor, pricing.zippiFeeMinor, pricing.chargeTotalMinor,
        ]
      );
      await client.query("commit");
      return result.rows[0];
    } catch (error) {
      await client.query("rollback").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async function paymentSetup(userId, rawPayload) {
    assertConfigured();
    const payload = validateCheckoutPayload(rawPayload);
    const offer = await fetchOffer(payload.offerId);
    assertFreshOneWayOffer(offer);
    const { services, pricing } = await priceCheckout(payload, offer);
    buildDuffelPassengers(payload.travelers, payload.contact, offer.passengers);

    if (payload.currency !== pricing.currency || payload.totalMinor !== pricing.chargeTotalMinor) {
      throw new FlightBookingError(409, "checkout_price_changed", "The live fare total changed. Return to review before paying.", {
        currency: pricing.currency,
        totalMinor: pricing.chargeTotalMinor,
      });
    }

    const fingerprint = checkoutFingerprint(userId, payload, offer, services, pricing);
    const session = await findOrCreateSession(userId, payload, offer, services, pricing, fingerprint);
    let intent = null;

    if (session.stripe_payment_intent_id) {
      intent = await stripe.paymentIntents.retrieve(session.stripe_payment_intent_id);
      if (intent.amount !== pricing.chargeTotalMinor || normalizeCurrency(intent.currency) !== pricing.currency) {
        throw new FlightBookingError(409, "payment_amount_changed", "The existing payment session has a different total.");
      }
    } else {
      intent = await stripe.paymentIntents.create({
        amount: pricing.chargeTotalMinor,
        currency: pricing.currency.toLowerCase(),
        payment_method_types: ["card"],
        receipt_email: payload.contact.email,
        description: `Zippi test flight ${payload.offerId}`,
        metadata: {
          booking_session_id: session.id,
          duffel_offer_id: payload.offerId,
          environment: "test",
        },
      }, { idempotencyKey: `flight-payment-${session.id}` });
    }

    if (!intent?.client_secret) throw new FlightBookingError(502, "stripe_setup_failed", "Stripe did not return a payment client secret.");
    await dbPool.query(
      `update flight_booking_sessions
          set stripe_payment_intent_id = $2, stripe_payment_status = $3, booking_status = 'awaiting_payment', updated_at = now()
        where id = $1`,
      [session.id, intent.id, intent.status]
    );
    return { paymentIntentClientSecret: intent.client_secret, bookingSessionId: session.id };
  }

  async function claimSession(userId, bookingSessionId) {
    const confirmed = await dbPool.query(
      "select * from flight_booking_sessions where id = $1 and user_id = $2",
      [bookingSessionId, userId]
    );
    const current = confirmed.rows[0];
    if (!current) throw new FlightBookingError(404, "booking_session_not_found", "Booking session not found.");
    if (current.booking_status === "confirmed" && current.confirmation_snapshot) return { confirmed: true, session: current };
    if (current.booking_status === "booking_unknown") {
      throw new FlightBookingError(409, "booking_outcome_unknown", "The airline booking outcome is still being reconciled. Do not try again.");
    }
    if (current.booking_status === "booking_failed_refund_pending") {
      throw new FlightBookingError(409, "refund_pending", "This booking failed and its Stripe refund requires attention.");
    }
    if (current.booking_status.startsWith("booking_failed")) {
      throw new FlightBookingError(409, current.failure_code || "booking_failed", current.failure_message || "This booking attempt failed.");
    }

    const claimed = await dbPool.query(
      `update flight_booking_sessions
          set booking_status = 'booking_in_progress', duffel_attempted_at = now(), updated_at = now()
        where id = $1 and user_id = $2 and booking_status in ('awaiting_payment','payment_paid')
        returning *`,
      [bookingSessionId, userId]
    );
    if (!claimed.rows[0]) {
      throw new FlightBookingError(409, "booking_in_progress", "This booking is already being processed. Do not submit it again.");
    }
    return { confirmed: false, session: claimed.rows[0] };
  }

  async function updateFailure(sessionId, status, code, message, extra = {}) {
    await dbPool.query(
      `update flight_booking_sessions set
         booking_status = $2, failure_code = $3, failure_message = $4,
         recovery_status = coalesce($5, recovery_status), stripe_refund_id = coalesce($6, stripe_refund_id),
         duffel_request_id = coalesce($7, duffel_request_id), updated_at = now()
       where id = $1`,
      [sessionId, status, code, message, extra.recoveryStatus || null, extra.refundId || null, extra.duffelRequestId || null]
    );
  }

  async function refundAfterDefinitiveFailure(session, code, message, duffelRequestId = null) {
    try {
      const refund = await stripe.refunds.create({
        payment_intent: session.stripe_payment_intent_id,
        reason: "requested_by_customer",
        metadata: { booking_session_id: session.id, failure_code: code },
      }, { idempotencyKey: `flight-refund-${session.id}` });
      await updateFailure(session.id, "booking_failed_refunded", code, message, {
        recoveryStatus: refund.status === "succeeded" ? "refunded" : "refund_pending",
        refundId: refund.id,
        duffelRequestId,
      });
      return;
    } catch (error) {
      await updateFailure(session.id, "booking_failed_refund_pending", code, message, {
        recoveryStatus: "refund_failed",
        duffelRequestId,
      });
      throw new FlightBookingError(502, "refund_pending", `${message} Stripe refund recovery requires attention.`);
    }
  }

  async function resetForSafeRetry(sessionId, code, message) {
    await dbPool.query(
      `update flight_booking_sessions
          set booking_status = 'payment_paid', failure_code = $2, failure_message = $3, updated_at = now()
        where id = $1`,
      [sessionId, code, message]
    );
  }

  async function confirmBooking(userId, bookingSessionId) {
    assertConfigured();
    const id = normalizeString(bookingSessionId);
    if (!id) throw new FlightBookingError(400, "missing_booking_session", "A booking session ID is required.");
    if (!isUUID(id)) throw new FlightBookingError(400, "invalid_booking_session", "The booking session ID is invalid.");
    const claim = await claimSession(userId, id);
    if (claim.confirmed) return claim.session.confirmation_snapshot;
    const session = claim.session;

    let intent;
    try {
      intent = await stripe.paymentIntents.retrieve(session.stripe_payment_intent_id);
    } catch (_) {
      await resetForSafeRetry(session.id, "stripe_verification_failed", "Stripe payment verification could not be completed.");
      throw new FlightBookingError(502, "stripe_verification_failed", "Payment verification is temporarily unavailable. Try confirmation again.");
    }
    await dbPool.query(
      "update flight_booking_sessions set stripe_payment_status = $2, updated_at = now() where id = $1",
      [session.id, intent.status]
    );
    if (intent.status !== "succeeded") {
      await dbPool.query(
        "update flight_booking_sessions set booking_status = 'awaiting_payment', updated_at = now() where id = $1",
        [session.id]
      );
      throw new FlightBookingError(402, "payment_not_completed", "Stripe payment has not completed.");
    }
    if (intent.amount !== Number(session.charge_total_minor) || normalizeCurrency(intent.currency) !== session.currency) {
      await refundAfterDefinitiveFailure(session, "stripe_amount_mismatch", "The verified Stripe payment did not match the booking total.");
      throw new FlightBookingError(409, "stripe_amount_mismatch", "Payment total did not match the booking and has been refunded.");
    }

    let offer;
    let services;
    let pricing;
    let passengers;
    try {
      offer = await fetchOffer(session.duffel_offer_id);
      assertFreshOneWayOffer(offer);
      const repriced = await priceCheckout(session.payload_snapshot, offer);
      services = repriced.services;
      pricing = repriced.pricing;
      if (pricing.currency !== session.currency || pricing.duffelTotalMinor !== Number(session.duffel_total_minor)) {
        throw new FlightBookingError(409, "price_changed", "The airline price changed before booking.");
      }
      passengers = buildDuffelPassengers(session.traveler_info, session.contact_info, offer.passengers);
    } catch (error) {
      if (error.code === "duffel_timeout" || error.status >= 500) {
        await resetForSafeRetry(session.id, error.code || "offer_check_failed", error.message || "Offer verification failed.");
        throw error;
      }
      await refundAfterDefinitiveFailure(session, error.code || "offer_unavailable", error.message || "The offer is no longer available.");
      throw new FlightBookingError(409, error.code || "offer_unavailable", `${error.message} Payment has been refunded.`);
    }

    const orderPayload = {
      data: {
        type: "instant",
        selected_offers: [session.duffel_offer_id],
        payments: [{
          type: "balance",
          currency: session.currency,
          amount: minorToDecimal(Number(session.duffel_total_minor), session.currency),
        }],
        passengers,
        metadata: {
          zippi_booking_session_id: session.id,
          stripe_payment_intent_id: session.stripe_payment_intent_id,
        },
      },
    };
    if (services.length) orderPayload.data.services = services.map(({ id: serviceId, quantity }) => ({ id: serviceId, quantity }));

    let orderResult;
    try {
      orderResult = await fetchDuffel("/air/orders", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(orderPayload),
      }, orderTimeoutMs);
    } catch (error) {
      await updateFailure(session.id, "booking_unknown", "duffel_timeout", "Duffel order creation timed out; outcome requires reconciliation.", {
        recoveryStatus: "manual_reconciliation_required",
      });
      throw new FlightBookingError(504, "booking_outcome_unknown", "The airline booking outcome is still being reconciled. Do not try again or submit another payment.");
    }

    const order = orderResult.json?.data;
    if (orderResult.response.status === 201 && order?.id) {
      const confirmation = buildConfirmation(order, session);
      await dbPool.query(
        `update flight_booking_sessions set
           booking_status = 'confirmed', stripe_payment_status = 'succeeded', duffel_order_id = $2,
           duffel_booking_reference = $3, duffel_request_id = $4, confirmation_snapshot = $5::jsonb,
           confirmed_at = now(), failure_code = null, failure_message = null, updated_at = now()
         where id = $1`,
        [session.id, order.id, order.booking_reference || null, orderResult.json?.meta?.request_id || null, JSON.stringify(confirmation)]
      );
      return confirmation;
    }

    const info = duffelErrorInfo(orderResult.json);
    const definitiveFailure = isDefinitiveDuffelOrderFailureStatus(orderResult.response.status);
    if (definitiveFailure) {
      await refundAfterDefinitiveFailure(session, info.code, info.message, info.requestId);
      throw new FlightBookingError(409, info.code, `${info.message} Payment has been refunded.`);
    }

    await updateFailure(session.id, "booking_unknown", info.code, info.message, {
      recoveryStatus: "manual_reconciliation_required",
      duffelRequestId: info.requestId,
    });
    throw new FlightBookingError(502, "booking_outcome_unknown", "The airline booking outcome is still being reconciled. Do not try again or submit another payment.");
  }

  return { paymentSetup, confirmBooking };
}

module.exports = {
  FlightBookingError,
  buildConfirmation,
  buildDuffelPassengers,
  calculatePricing,
  createFlightBookingService,
  currencyExponent,
  decimalToMinor,
  endpointError,
  isDefinitiveDuffelOrderFailureStatus,
  minorToDecimal,
  requestedServiceQuantities,
  resolveSelectedServices,
  validateCheckoutPayload,
};
