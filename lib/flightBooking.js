const { createHash } = require("crypto");
const { recoverStaleBookingClaim } = require("./flightRecovery");
const { currencyExponent, decimalToMinorExact, minorToDecimal } = require("./currencyAmount");

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

const DEFINITIVE_DUFFEL_ORDER_FAILURE_STATUSES = new Set([400, 401, 402, 403, 404, 405, 413, 415, 422]);

function decimalToMinor(value, currency) {
  try {
    return decimalToMinorExact(value, currency);
  } catch (error) {
    throw new FlightBookingError(502, "invalid_provider_price", error.message);
  }
}

function normalizeString(value) {
  return String(value || "").trim();
}

function normalizeCurrency(value) {
  return normalizeString(value).toUpperCase();
}

function minorFactor(currency) {
  return 10 ** currencyExponent(currency);
}

function ceilMinor(value) {
  if (!Number.isFinite(value) || value < 0) {
    throw new FlightBookingError(502, "invalid_price_conversion", "The converted price could not be calculated.");
  }
  return Math.ceil(value - 1e-9);
}

function majorFromMinor(minor, currency) {
  return Number(minor) / minorFactor(currency);
}

function convertMajorAmount(amount, fromCurrency, toCurrency, exchangeRates) {
  const from = normalizeCurrency(fromCurrency);
  const to = normalizeCurrency(toCurrency);
  if (!from || !to) throw new FlightBookingError(400, "missing_currency", "A provider and customer currency are required.");
  if (from === to) return { amount, rate: 1, source: exchangeRates?.source || "same_currency" };

  const base = normalizeCurrency(exchangeRates?.base);
  const rates = exchangeRates?.rates || {};
  const toRate = Number(rates[to]);
  const fromRate = Number(rates[from]);
  let rate = null;
  if (from === base && Number.isFinite(toRate) && toRate > 0) {
    rate = toRate;
  } else if (to === base && Number.isFinite(fromRate) && fromRate > 0) {
    rate = 1 / fromRate;
  } else if (Number.isFinite(fromRate) && fromRate > 0 && Number.isFinite(toRate) && toRate > 0) {
    rate = toRate / fromRate;
  }
  if (!Number.isFinite(rate) || rate <= 0) {
    throw new FlightBookingError(503, "exchange_rate_unavailable", `A ${from} to ${to} exchange rate is not available right now.`);
  }
  return { amount: amount * rate, rate, source: exchangeRates?.source || "exchange_rates_cache" };
}

function roundingIncrementMinor(currency) {
  const code = normalizeCurrency(currency);
  const factor = minorFactor(code);
  if (["CAD", "USD", "EUR"].includes(code)) return 5 * factor;
  if (code === "COP") return 500 * factor;
  return factor;
}

function roundUpMinor(minor, incrementMinor) {
  if (!Number.isSafeInteger(minor) || minor < 0) {
    throw new FlightBookingError(500, "invalid_quote", "The server produced an invalid rounded price.");
  }
  if (!Number.isSafeInteger(incrementMinor) || incrementMinor <= 0) return minor;
  const remainder = minor % incrementMinor;
  return remainder === 0 ? minor : minor + (incrementMinor - remainder);
}

function pricingSessionProviderCurrency(session) {
  return normalizeCurrency(session?.provider_currency || session?.currency);
}

function pricingSessionCustomerCurrency(session) {
  return normalizeCurrency(session?.customer_currency || session?.currency);
}

function pricingSessionProviderTotalMinor(session) {
  return Number(session?.provider_total_minor ?? session?.duffel_total_minor);
}

function pricingSessionCustomerTotalMinor(session) {
  return Number(session?.customer_total_minor ?? session?.charge_total_minor);
}

function pricingSessionCustomerFeeMinor(session) {
  return Number(session?.customer_zippi_fee_minor ?? session?.zippi_fee_minor);
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

function normalizeTravelerType(value) {
  const type = normalizeString(value).toLowerCase();
  return ["adult", "child", "infant_without_seat"].includes(type) ? type : "";
}

function ageOnDate(dateOfBirthISO, referenceDate) {
  if (!isISODate(dateOfBirthISO) || !(referenceDate instanceof Date) || Number.isNaN(referenceDate.getTime())) return null;
  const [year, month, day] = dateOfBirthISO.split("-").map(Number);
  let age = referenceDate.getUTCFullYear() - year;
  const referenceMonth = referenceDate.getUTCMonth() + 1;
  const referenceDay = referenceDate.getUTCDate();
  if (referenceMonth < month || (referenceMonth === month && referenceDay < day)) age -= 1;
  return age;
}

function offerDepartureDate(offer) {
  const firstSlice = Array.isArray(offer?.slices) ? offer.slices[0] : null;
  const firstSegment = Array.isArray(firstSlice?.segments) ? firstSlice.segments[0] : null;
  const raw = normalizeString(firstSegment?.departing_at || firstSlice?.departure_date);
  const parsed = raw ? new Date(raw.length === 10 ? `${raw}T00:00:00Z` : raw) : null;
  return parsed && !Number.isNaN(parsed.getTime()) ? parsed : null;
}

function validateTravelerTypesForOffer(travelers, offer) {
  const departure = offerDepartureDate(offer);
  if (!departure) throw new FlightBookingError(502, "missing_offer_departure", "Duffel returned an offer without a valid departure date.");

  travelers.forEach((traveler, index) => {
    const type = normalizeTravelerType(traveler?.travelerType);
    const age = ageOnDate(traveler?.dateOfBirthISO, departure);
    const compatible = type === "adult" ? age >= 18
      : type === "child" ? age >= 2 && age < 18
        : type === "infant_without_seat" ? age >= 0 && age < 2
          : false;
    if (!compatible) {
      throw new FlightBookingError(
        400,
        "traveler_type_age_mismatch",
        `Traveler ${index + 1}'s date of birth does not match traveler type ${type || "unknown"}.`
      );
    }
  });
}

function offerTravelEndDate(offer) {
  const slices = Array.isArray(offer?.slices) ? offer.slices : [];
  const timestamps = slices.flatMap((slice) => {
    const segments = Array.isArray(slice?.segments) ? slice.segments : [];
    return segments.flatMap((segment) => [segment?.departing_at, segment?.arriving_at]);
  }).map((value) => new Date(value)).filter((date) => !Number.isNaN(date.getTime()));
  return timestamps.length ? new Date(Math.max(...timestamps.map((date) => date.getTime()))) : offerDepartureDate(offer);
}

function offerCountryCodes(offer) {
  const codes = new Set();
  const countryCode = (point) => {
    const code = normalizeString(
      point?.iata_country_code || point?.country_code || point?.city?.country_code || point?.city?.country?.code
    ).toUpperCase();
    return /^[A-Z]{2}$/.test(code) ? code : "";
  };
  const slices = Array.isArray(offer?.slices) ? offer.slices : [];
  if (!slices.length) {
    throw new FlightBookingError(502, "missing_offer_geography", "Duffel returned an offer without itinerary geography.");
  }
  slices.forEach((slice) => {
    const segments = Array.isArray(slice?.segments) ? slice.segments : [];
    if (!segments.length) {
      throw new FlightBookingError(502, "missing_offer_geography", "Duffel returned an itinerary without route segments.");
    }
    segments.forEach((segment) => {
      const origin = countryCode(segment?.origin);
      const destination = countryCode(segment?.destination);
      if (!origin || !destination) {
        throw new FlightBookingError(502, "missing_offer_geography", "Duffel returned an itinerary with unresolved country information.");
      }
      codes.add(origin);
      codes.add(destination);
    });
  });
  return codes;
}

function validateInternationalTravelerDocuments(travelers, offer) {
  if (offerCountryCodes(offer).size < 2) return;
  const travelEnd = offerTravelEndDate(offer);
  if (!travelEnd) throw new FlightBookingError(502, "missing_offer_travel_date", "Duffel returned an international offer without valid travel dates.");
  const travelEndISO = travelEnd.toISOString().slice(0, 10);
  travelers.forEach((traveler, index) => {
    const nationality = normalizeString(traveler?.nationality).toUpperCase();
    const passportNumber = normalizeString(traveler?.passportNumber);
    const passportCountry = normalizeString(traveler?.passportCountry).toUpperCase();
    const passportExpiry = normalizeString(traveler?.passportExpiryISO);
    if (!/^[A-Z]{2}$/.test(nationality) || !passportNumber || !/^[A-Z]{2}$/.test(passportCountry) || !isISODate(passportExpiry)) {
      throw new FlightBookingError(400, "international_documents_required", `Traveler ${index + 1} needs nationality and complete passport details for this international itinerary.`);
    }
    if (passportExpiry < travelEndISO) {
      throw new FlightBookingError(400, "passport_expired_for_trip", `Traveler ${index + 1}'s passport must remain valid through the itinerary.`);
    }
  });
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
  const returnOfferId = normalizeString(payload.returnOfferId);
  if (returnOfferId && returnOfferId !== offerId) {
    throw new FlightBookingError(
      422,
      "atomic_round_trip_required",
      "Round trips must use one bundled Duffel offer ID. Independent outbound and return offers cannot be combined."
    );
  }

  const travelers = Array.isArray(payload.travelers) ? payload.travelers : [];
  if (!travelers.length || travelers.length > 9) {
    throw new FlightBookingError(400, "invalid_travelers", "Between 1 and 9 travelers are required.");
  }

  const normalizedTravelers = travelers.map((traveler, index) => {
    const travelerType = normalizeTravelerType(traveler?.travelerType);
    if (!travelerType) {
      throw new FlightBookingError(400, "invalid_traveler_type", `Traveler ${index + 1} needs adult, child, or infant_without_seat.`);
    }
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
    const nationality = normalizeString(traveler?.nationality).toUpperCase();
    if (nationality && !/^[A-Z]{2}$/.test(nationality)) {
      throw new FlightBookingError(400, "invalid_nationality", `Traveler ${index + 1} needs a two-letter nationality code.`);
    }
    return { ...traveler, travelerType, nationality: nationality || null };
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
    returnOfferId: returnOfferId || null,
    travelers: normalizedTravelers,
    contact: { email, phone },
    currency: (() => {
      const currency = normalizeCurrency(payload.currency);
      if (!currency) throw new FlightBookingError(400, "missing_currency", "A customer currency is required.");
      return currency;
    })(),
    totalMinor: clientTotalMinor,
  };
}

function validateQuotePayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new FlightBookingError(400, "invalid_request", "Invalid quote payload.");
  }
  const offerId = normalizeString(payload.offerId);
  if (!offerId) throw new FlightBookingError(400, "missing_offer", "A Duffel offer is required.");
  const returnOfferId = normalizeString(payload.returnOfferId);
  if (returnOfferId && returnOfferId !== offerId) {
    throw new FlightBookingError(422, "atomic_round_trip_required", "Round trips must use one bundled Duffel offer ID.");
  }
  const currency = normalizeCurrency(payload.currency);
  if (!currency) throw new FlightBookingError(400, "missing_currency", "A customer currency is required.");
  return { ...payload, offerId, returnOfferId: returnOfferId || null, currency };
}

function assertFreshOffer(offer) {
  if (!offer?.id) throw new FlightBookingError(502, "invalid_offer", "Duffel returned an invalid offer.");
  const slices = Array.isArray(offer.slices) ? offer.slices : [];
  if (slices.length < 1 || slices.length > 2) {
    throw new FlightBookingError(422, "unsupported_itinerary", "Checkout supports one-way or bundled round-trip Duffel offers.");
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

function calculatePricing(offer, services, customerCurrency, zippiFeeMinor, exchangeRates, fxMarginBps = 500) {
  const providerCurrency = normalizeCurrency(offer?.total_currency);
  if (!providerCurrency) throw new FlightBookingError(502, "invalid_offer_currency", "Duffel returned an invalid offer currency.");
  const providerOfferMinor = decimalToMinor(offer?.total_amount, providerCurrency);
  let providerTaxesMinor = offer?.tax_amount == null ? null : decimalToMinor(offer.tax_amount, providerCurrency);
  const providerBaseFareMinor = offer?.base_amount == null
    ? (providerTaxesMinor == null ? providerOfferMinor : providerOfferMinor - providerTaxesMinor)
    : decimalToMinor(offer.base_amount, providerCurrency);
  if (providerTaxesMinor == null && offer?.base_amount != null && providerBaseFareMinor !== providerOfferMinor) {
    providerTaxesMinor = providerOfferMinor - providerBaseFareMinor;
  }
  if (providerBaseFareMinor < 0
      || (providerTaxesMinor != null
        && (providerTaxesMinor < 0 || providerBaseFareMinor + providerTaxesMinor !== providerOfferMinor))) {
    throw new FlightBookingError(502, "invalid_provider_price", "Duffel returned inconsistent fare and tax totals.");
  }

  let providerServicesMinor = 0;
  for (const service of services) {
    if (service.currency !== providerCurrency) {
      throw new FlightBookingError(409, "service_currency_mismatch", "A selected extra uses a different currency.");
    }
    providerServicesMinor += service.totalMinor;
  }
  const providerTotalMinor = providerOfferMinor + providerServicesMinor;
  const customerCode = normalizeCurrency(customerCurrency);
  if (!customerCode) throw new FlightBookingError(400, "missing_currency", "A customer currency is required.");

  const fx = convertMajorAmount(1, providerCurrency, customerCode, exchangeRates);
  const fxMultiplier = providerCurrency === customerCode ? 1 : (1 + (Number(fxMarginBps) / 10_000));
  const toCustomerMinor = (minor, sourceCurrency) => {
    const major = majorFromMinor(minor, sourceCurrency);
    const converted = convertMajorAmount(major, sourceCurrency, customerCode, exchangeRates).amount * fxMultiplier;
    return ceilMinor(converted * minorFactor(customerCode));
  };

  const customerBaseFareMinor = toCustomerMinor(providerBaseFareMinor, providerCurrency);
  const customerTaxesMinor = providerTaxesMinor == null ? null : toCustomerMinor(providerTaxesMinor, providerCurrency);
  const customerServicesMinor = providerServicesMinor > 0 ? toCustomerMinor(providerServicesMinor, providerCurrency) : 0;
  const customerConvertedMinor = customerBaseFareMinor + (customerTaxesMinor ?? 0) + customerServicesMinor;
  const customerFeeMinor = Number(zippiFeeMinor);
  if (!Number.isSafeInteger(customerFeeMinor) || customerFeeMinor < 0) {
    throw new FlightBookingError(500, "invalid_fee_configuration", "The booking fee configuration is invalid.");
  }
  const customerPreRoundMinor = customerConvertedMinor + customerFeeMinor;
  const customerRoundingIncrementMinor = roundingIncrementMinor(customerCode);
  const customerTotalMinor = roundUpMinor(customerPreRoundMinor, customerRoundingIncrementMinor);
  const customerRoundingAdjustmentMinor = customerTotalMinor - customerPreRoundMinor;

  return {
    providerCurrency,
    providerOfferMinor,
    providerBaseFareMinor,
    providerTaxesMinor,
    providerServicesMinor,
    providerTotalMinor,
    customerCurrency: customerCode,
    customerFxRate: fx.rate,
    customerFxSource: fx.source,
    customerFxMarginBps: Number(fxMarginBps),
    customerBaseFareMinor,
    customerTaxesMinor,
    customerServicesMinor,
    customerConvertedMinor,
    customerZippiFeeMinor: customerFeeMinor,
    customerPreRoundMinor,
    customerRoundingIncrementMinor,
    customerRoundingAdjustmentMinor,
    customerTotalMinor,
    currency: customerCode,
    offerMinor: providerOfferMinor,
    baseFareMinor: customerBaseFareMinor,
    taxesMinor: customerTaxesMinor,
    servicesMinor: customerServicesMinor,
    duffelTotalMinor: providerTotalMinor,
    zippiFeeMinor: customerFeeMinor,
    chargeTotalMinor: customerTotalMinor,
  };
}

function buildPricingQuote(pricing) {
  const required = [
    pricing.providerBaseFareMinor,
    pricing.providerOfferMinor,
    pricing.providerServicesMinor,
    pricing.providerTotalMinor,
    pricing.customerBaseFareMinor,
    pricing.customerConvertedMinor,
    pricing.customerZippiFeeMinor,
    pricing.customerPreRoundMinor,
    pricing.customerRoundingIncrementMinor,
    pricing.customerRoundingAdjustmentMinor,
    pricing.customerTotalMinor,
  ];
  if (!required.every((value) => Number.isSafeInteger(value) && value >= 0)
      || (pricing.providerTaxesMinor != null && (!Number.isSafeInteger(pricing.providerTaxesMinor) || pricing.providerTaxesMinor < 0))
      || (pricing.customerTaxesMinor != null && (!Number.isSafeInteger(pricing.customerTaxesMinor) || pricing.customerTaxesMinor < 0))
      || (pricing.providerTaxesMinor != null && pricing.providerBaseFareMinor + pricing.providerTaxesMinor !== pricing.providerOfferMinor)
      || pricing.providerOfferMinor + pricing.providerServicesMinor !== pricing.providerTotalMinor
      || pricing.customerBaseFareMinor + (pricing.customerTaxesMinor ?? 0) + pricing.customerServicesMinor !== pricing.customerConvertedMinor
      || pricing.customerConvertedMinor + pricing.customerZippiFeeMinor !== pricing.customerPreRoundMinor
      || pricing.customerPreRoundMinor + pricing.customerRoundingAdjustmentMinor !== pricing.customerTotalMinor) {
    throw new FlightBookingError(500, "invalid_quote", "The server produced an inconsistent checkout quote.");
  }
  return {
    currency: pricing.customerCurrency,
    lineItems: {
      baseFareMinor: pricing.customerBaseFareMinor,
      taxesMinor: pricing.customerTaxesMinor,
      servicesMinor: pricing.customerServicesMinor,
      zippiFeeMinor: pricing.customerZippiFeeMinor,
      preRoundMinor: pricing.customerPreRoundMinor,
      roundingAdjustmentMinor: pricing.customerRoundingAdjustmentMinor,
    },
    offerTotalMinor: pricing.customerConvertedMinor,
    duffelTotalMinor: pricing.providerTotalMinor,
    totalMinor: pricing.customerTotalMinor,
    provider: {
      currency: pricing.providerCurrency,
      lineItems: {
        baseFareMinor: pricing.providerBaseFareMinor,
        taxesMinor: pricing.providerTaxesMinor,
        servicesMinor: pricing.providerServicesMinor,
      },
      offerTotalMinor: pricing.providerOfferMinor,
      totalMinor: pricing.providerTotalMinor,
    },
    customer: {
      currency: pricing.customerCurrency,
      fxRate: pricing.customerFxRate,
      fxSource: pricing.customerFxSource,
      fxMarginBps: pricing.customerFxMarginBps,
      convertedMinor: pricing.customerConvertedMinor,
      lineItems: {
        baseFareMinor: pricing.customerBaseFareMinor,
        taxesMinor: pricing.customerTaxesMinor,
        servicesMinor: pricing.customerServicesMinor,
        zippiFeeMinor: pricing.customerZippiFeeMinor,
        preRoundMinor: pricing.customerPreRoundMinor,
        roundingAdjustmentMinor: pricing.customerRoundingAdjustmentMinor,
      },
      roundingIncrementMinor: pricing.customerRoundingIncrementMinor,
      totalMinor: pricing.customerTotalMinor,
    },
  };
}

function normalizeAvailableServices(services, requestedType = "") {
  const typeFilter = normalizeString(requestedType).toLowerCase();
  const normalized = (Array.isArray(services) ? services : []).map((service) => {
    const metadata = service?.metadata && typeof service.metadata === "object" ? service.metadata : {};
    const providerType = normalizeString(service?.type).toLowerCase();
    const baggageType = normalizeString(metadata.type || service?.baggage_type).toLowerCase();
    const isBaggage = providerType === "baggage" || ["checked", "carry_on", "cabin_bag", "personal_item", "small_carry_on"].includes(providerType) || Boolean(baggageType);
    const isCfar = providerType === "cancel_for_any_reason" || providerType === "cfar";
    return {
      ...service,
      ...(isBaggage ? { type: baggageType || providerType } : {}),
      ...(isCfar ? {
        type: "cancel_for_any_reason",
        coverage_percentage: service?.coverage_percentage ?? metadata.coverage_percentage ?? null,
        expires_at: service?.expires_at ?? metadata.expires_at ?? null,
      } : {}),
      maximum_quantity: Number.isInteger(Number(service?.maximum_quantity)) ? Number(service.maximum_quantity) : 1,
    };
  });

  if (!typeFilter) return normalized;
  if (typeFilter === "baggage") {
    return normalized.filter((service) => ["checked", "carry_on", "cabin_bag", "personal_item", "small_carry_on"].includes(service.type));
  }
  if (typeFilter === "cancel_for_any_reason" || typeFilter === "cfar") {
    return normalized.filter((service) => service.type === "cancel_for_any_reason");
  }
  return normalized.filter((service) => normalizeString(service.type).toLowerCase() === typeFilter);
}

function sessionPricingQuote(session) {
  const providerCurrency = pricingSessionProviderCurrency(session);
  const customerCurrency = pricingSessionCustomerCurrency(session);
  const providerOfferMinor = Number(session.provider_offer_minor ?? session.offer_minor);
  const snapshot = session.offer_snapshot || {};
  const persistedBase = session.base_fare_minor == null ? null : Number(session.base_fare_minor);
  const persistedTaxes = session.taxes_minor == null ? null : Number(session.taxes_minor);
  const taxesMinor = persistedBase == null
    ? (snapshot.taxAmount == null ? null : decimalToMinor(snapshot.taxAmount, providerCurrency))
    : persistedTaxes;
  const providerBaseFareMinor = persistedBase ?? (snapshot.baseAmount == null
    ? (taxesMinor == null ? providerOfferMinor : providerOfferMinor - taxesMinor)
    : decimalToMinor(snapshot.baseAmount, providerCurrency));
  const customerConvertedMinor = Number(session.customer_converted_minor ?? session.offer_minor ?? providerOfferMinor);
  const customerFeeMinor = pricingSessionCustomerFeeMinor(session);
  const customerPreRoundMinor = Number(session.customer_pre_round_minor ?? (customerConvertedMinor + customerFeeMinor));
  return buildPricingQuote({
    providerCurrency,
    providerBaseFareMinor,
    providerTaxesMinor: taxesMinor,
    providerOfferMinor,
    providerServicesMinor: Number(session.provider_services_minor ?? session.services_minor ?? 0),
    providerTotalMinor: pricingSessionProviderTotalMinor(session),
    customerCurrency,
    customerFxRate: Number(session.customer_fx_rate ?? 1),
    customerFxSource: session.customer_fx_source || "legacy_session",
    customerFxMarginBps: Number(session.customer_fx_margin_bps ?? 0),
    customerBaseFareMinor: Number(session.customer_base_fare_minor ?? session.base_fare_minor ?? providerBaseFareMinor),
    customerTaxesMinor: session.customer_taxes_minor == null ? taxesMinor : Number(session.customer_taxes_minor),
    customerServicesMinor: Number(session.customer_services_minor ?? session.services_minor ?? 0),
    customerConvertedMinor,
    customerZippiFeeMinor: customerFeeMinor,
    customerPreRoundMinor,
    customerRoundingIncrementMinor: Number(session.customer_rounding_increment_minor ?? minorFactor(customerCurrency)),
    customerRoundingAdjustmentMinor: Number(session.customer_rounding_adjustment_minor ?? 0),
    customerTotalMinor: pricingSessionCustomerTotalMinor(session),
  });
}

function buildDuffelPassengers(travelers, contact, offerPassengers) {
  if (!Array.isArray(offerPassengers) || offerPassengers.length !== travelers.length) {
    throw new FlightBookingError(409, "passenger_count_changed", "The traveler count no longer matches this fare.");
  }

  const passengerRefsByType = new Map();
  offerPassengers.forEach((passengerRef) => {
    const type = normalizeTravelerType(passengerRef?.type);
    if (!type) throw new FlightBookingError(502, "invalid_passenger_type", "Duffel returned an unsupported passenger type.");
    const refs = passengerRefsByType.get(type) || [];
    refs.push(passengerRef);
    passengerRefsByType.set(type, refs);
  });

  const passengers = travelers.map((traveler, index) => {
    const firstName = normalizeString(traveler.firstName);
    const middleName = normalizeString(traveler.middleName);
    const travelerType = normalizeTravelerType(traveler.travelerType);
    const passengerRef = (passengerRefsByType.get(travelerType) || []).shift();
    const passenger = {
      id: normalizeString(passengerRef?.id),
      title: normalizeTitle(traveler.title),
      given_name: middleName ? `${firstName} ${middleName}` : firstName,
      family_name: normalizeString(traveler.lastName),
      born_on: normalizeString(traveler.dateOfBirthISO),
      gender: normalizeGender(traveler.gender),
      email: contact.email,
      phone_number: contact.phone,
    };
    if (!passenger.id) {
      throw new FlightBookingError(409, "passenger_type_changed", `Duffel no longer has a matching ${travelerType} passenger reference.`);
    }
    const nationality = normalizeString(traveler.nationality).toUpperCase();
    if (nationality) passenger.nationality = nationality;

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
  if ([...passengerRefsByType.values()].some((refs) => refs.length)) {
    throw new FlightBookingError(409, "passenger_type_changed", "The traveler types no longer match this fare.");
  }
  return passengers;
}

function checkoutFingerprint(userId, payload, offer, services, pricing) {
  const fingerprintPayload = {
    userId,
    offerId: payload.offerId,
    offerExpiresAt: offer.expires_at || null,
    travelers: payload.travelers,
    contact: payload.contact,
    services: services.map(({ id, quantity }) => ({ id, quantity })),
    providerCurrency: pricing.providerCurrency,
    providerTotalMinor: pricing.providerTotalMinor,
    customerCurrency: pricing.customerCurrency,
    totalMinor: pricing.customerTotalMinor,
  };
  return createHash("sha256").update(JSON.stringify(fingerprintPayload)).digest("hex");
}

function summarizeOffer(offer) {
  return {
    id: offer.id,
    expiresAt: offer.expires_at || null,
    totalAmount: offer.total_amount,
    totalCurrency: offer.total_currency,
    baseAmount: offer.base_amount ?? null,
    taxAmount: offer.tax_amount ?? null,
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
  return DEFINITIVE_DUFFEL_ORDER_FAILURE_STATUSES.has(Number(status));
}

function staleBookingClaimDisposition(session, now = Date.now(), leaseMs = 5 * 60 * 1000) {
  if (session?.booking_status !== "booking_in_progress") return "not_claimed";
  const updatedAt = Date.parse(session?.updated_at);
  if (!Number.isFinite(updatedAt) || now - updatedAt < leaseMs) return "active";
  return session?.duffel_post_started_at ? "outcome_unknown" : "safe_retry";
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
    currency: pricingSessionCustomerCurrency(session),
    totalMinor: pricingSessionCustomerTotalMinor(session),
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
    getExchangeRates = null,
    zippiFeeMinor = 499,
    fxMarginBps = 500,
    orderTimeoutMs = 130000,
    bookingClaimLeaseMs = 5 * 60 * 1000,
  } = options;

  function assertConfigured() {
    if (!enabled) throw new FlightBookingError(403, "test_booking_disabled", "Flight test booking is disabled on this server.");
    if (!dbPool) throw new FlightBookingError(500, "database_not_configured", "Flight checkout database is not configured.");
    if (!stripe) throw new FlightBookingError(500, "stripe_not_configured", "Stripe test mode is not configured.");
    if (duffelMode !== "TEST" || !normalizeString(duffelToken).startsWith("duffel_test_")) {
      throw new FlightBookingError(500, "duffel_test_token_required", "A Duffel test token with booking permission is required.");
    }
  }

  function assertQuoteConfigured() {
    if (!enabled) throw new FlightBookingError(403, "test_booking_disabled", "Flight test booking is disabled on this server.");
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
    const exchangeRates = await getExchangeRates?.();
    if (!exchangeRates?.rates) {
      throw new FlightBookingError(503, "exchange_rates_unavailable", "Exchange rates are temporarily unavailable.");
    }
    const quantities = requestedServiceQuantities(payload);
    let services = [];
    try {
      services = resolveSelectedServices(payload, offer, []);
    } catch (error) {
      if (error.code !== "service_unavailable" || !quantities.size) throw error;
      const seatMaps = await fetchSeatMaps(payload.offerId);
      services = resolveSelectedServices(payload, offer, seatMaps);
    }
    const pricing = calculatePricing(offer, services, payload.currency, zippiFeeMinor, exchangeRates, fxMarginBps);
    return { services, pricing };
  }

  async function quoteCheckout(rawPayload) {
    assertQuoteConfigured();
    const payload = validateQuotePayload(rawPayload);
    const offer = await fetchOffer(payload.offerId);
    assertFreshOffer(offer);
    const { services, pricing } = await priceCheckout(payload, offer);
    return {
      offerId: payload.offerId,
      tripType: Array.isArray(offer.slices) && offer.slices.length === 2 ? "round_trip" : "one_way",
      expiresAt: offer.expires_at || null,
      quote: buildPricingQuote(pricing),
      selectedServices: services.map(({ id, quantity, totalMinor }) => ({ id, quantity, totalMinor })),
    };
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
           traveler_info, contact_info, selected_services, currency, base_fare_minor, taxes_minor,
           offer_minor, services_minor, duffel_total_minor, zippi_fee_minor, charge_total_minor,
           provider_currency, provider_offer_minor, provider_services_minor, provider_total_minor,
           customer_currency, customer_fx_rate, customer_fx_source, customer_fx_margin_bps,
           customer_base_fare_minor, customer_taxes_minor, customer_services_minor, customer_converted_minor,
           customer_zippi_fee_minor, customer_pre_round_minor, customer_rounding_increment_minor,
           customer_rounding_adjustment_minor, customer_total_minor,
           stripe_payment_status, booking_status
         ) values ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14,$15,$16,$17,
                   $18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,
                   'not_created','payment_setup')
         returning *`,
        [
          id, userId, fingerprint, payload.offerId, JSON.stringify(summarizeOffer(offer)), JSON.stringify(payload),
          JSON.stringify(payload.travelers), JSON.stringify(payload.contact), JSON.stringify(services), pricing.customerCurrency,
          pricing.providerBaseFareMinor, pricing.providerTaxesMinor, pricing.providerOfferMinor, pricing.providerServicesMinor,
          pricing.providerTotalMinor, pricing.customerZippiFeeMinor, pricing.customerTotalMinor,
          pricing.providerCurrency, pricing.providerOfferMinor, pricing.providerServicesMinor, pricing.providerTotalMinor,
          pricing.customerCurrency, pricing.customerFxRate, pricing.customerFxSource, pricing.customerFxMarginBps,
          pricing.customerBaseFareMinor, pricing.customerTaxesMinor, pricing.customerServicesMinor, pricing.customerConvertedMinor,
          pricing.customerZippiFeeMinor, pricing.customerPreRoundMinor, pricing.customerRoundingIncrementMinor,
          pricing.customerRoundingAdjustmentMinor, pricing.customerTotalMinor,
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
    assertFreshOffer(offer);
    const { services, pricing } = await priceCheckout(payload, offer);
    validateTravelerTypesForOffer(payload.travelers, offer);
    validateInternationalTravelerDocuments(payload.travelers, offer);
    buildDuffelPassengers(payload.travelers, payload.contact, offer.passengers);

    if (payload.currency !== pricing.customerCurrency || payload.totalMinor !== pricing.customerTotalMinor) {
      throw new FlightBookingError(409, "checkout_price_changed", "The live fare total changed. Return to review before paying.", {
        currency: pricing.customerCurrency,
        totalMinor: pricing.customerTotalMinor,
        quote: buildPricingQuote(pricing),
      });
    }

    const fingerprint = checkoutFingerprint(userId, payload, offer, services, pricing);
    let session = await findOrCreateSession(userId, payload, offer, services, pricing, fingerprint);
    let intent = null;

    if (session.stripe_payment_intent_id) {
      intent = await stripe.paymentIntents.retrieve(session.stripe_payment_intent_id);
      if (intent.status === "canceled") {
        const canceled = await dbPool.query(
          `update flight_booking_sessions
              set booking_status = 'payment_canceled', stripe_payment_status = $3, updated_at = now()
            where id = $1 and user_id = $2 and booking_status in ('payment_setup','awaiting_payment')
            returning *`,
          [session.id, userId, intent.status]
        );
        if (!canceled.rows[0]) {
          throw new FlightBookingError(409, "booking_session_advanced", "This booking session already advanced and cannot be restarted.");
        }
        session = await findOrCreateSession(userId, { ...payload, bookingSessionId: null }, offer, services, pricing, fingerprint);
        intent = await stripe.paymentIntents.create({
          amount: pricing.customerTotalMinor,
          currency: pricing.customerCurrency.toLowerCase(),
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
      if (intent.amount !== pricing.customerTotalMinor || normalizeCurrency(intent.currency) !== pricing.customerCurrency) {
        throw new FlightBookingError(409, "payment_amount_changed", "The existing payment session has a different total.");
      }
    } else {
      intent = await stripe.paymentIntents.create({
        amount: pricing.customerTotalMinor,
        currency: pricing.customerCurrency.toLowerCase(),
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
    const setupUpdate = await dbPool.query(
      `update flight_booking_sessions
          set stripe_payment_intent_id = $2, stripe_payment_status = $3, booking_status = 'awaiting_payment', updated_at = now()
        where id = $1 and user_id = $4
          and booking_status in ('payment_setup','awaiting_payment')
          and (stripe_payment_intent_id is null or stripe_payment_intent_id = $2)
        returning *`,
      [session.id, intent.id, intent.status, userId]
    );
    if (!setupUpdate.rows[0]) {
      throw new FlightBookingError(409, "booking_session_advanced", "This booking session already advanced and cannot be reset for payment.");
    }
    return {
      paymentIntentClientSecret: intent.client_secret,
      bookingSessionId: session.id,
      quote: buildPricingQuote(pricing),
    };
  }

  async function getBookingStatus(userId, bookingSessionId) {
    assertConfigured();
    const id = normalizeString(bookingSessionId);
    if (!id) throw new FlightBookingError(400, "missing_booking_session", "A booking session ID is required.");
    if (!isUUID(id)) throw new FlightBookingError(400, "invalid_booking_session", "The booking session ID is invalid.");

    const result = await dbPool.query(
      "select * from flight_booking_sessions where id = $1 and user_id = $2",
      [id, userId]
    );
    let session = result.rows[0];
    if (!session) throw new FlightBookingError(404, "booking_session_not_found", "Booking session not found.");

    if (session.booking_status === "booking_in_progress") {
      const recovered = await recoverStaleBookingClaim(dbPool, {
        sessionId: id,
        leaseMs: bookingClaimLeaseMs,
      });
      if (recovered.session) session = recovered.session;
    }

    if (session.stripe_payment_intent_id && ["payment_setup", "awaiting_payment", "payment_paid"].includes(session.booking_status)) {
      let intent;
      try {
        intent = await stripe.paymentIntents.retrieve(session.stripe_payment_intent_id);
      } catch (_) {
        throw new FlightBookingError(502, "stripe_verification_failed", "Payment status is temporarily unavailable.");
      }
      const paymentMatches = intent.amount === pricingSessionCustomerTotalMinor(session)
        && normalizeCurrency(intent.currency) === pricingSessionCustomerCurrency(session);
      const nextBookingStatus = intent.status === "succeeded" && paymentMatches ? "payment_paid" : session.booking_status;
      const updated = await dbPool.query(
        `update flight_booking_sessions
            set stripe_payment_status = $3, booking_status = $4, updated_at = now()
          where id = $1 and user_id = $2
            and booking_status in ('payment_setup','awaiting_payment','payment_paid')
          returning *`,
        [id, userId, intent.status, nextBookingStatus]
      );
      if (updated.rows[0]) {
        session = updated.rows[0];
      } else {
        const current = await dbPool.query(
          "select * from flight_booking_sessions where id = $1 and user_id = $2",
          [id, userId]
        );
        session = current.rows[0];
        if (!session) throw new FlightBookingError(404, "booking_session_not_found", "Booking session not found.");
      }
      if (intent.status === "succeeded" && !paymentMatches) {
        throw new FlightBookingError(409, "stripe_amount_mismatch", "The completed payment does not match this booking total and requires review.");
      }
    }

    return {
      bookingSessionId: session.id,
      status: session.booking_status,
      paymentStatus: session.stripe_payment_status,
      recoveryStatus: session.recovery_status || null,
      failure: session.failure_code ? { code: session.failure_code, message: session.failure_message || null } : null,
      quote: sessionPricingQuote(session),
      confirmation: session.confirmation_snapshot || null,
      updatedAt: session.updated_at || null,
    };
  }

  async function claimSession(userId, bookingSessionId) {
    const confirmed = await dbPool.query(
      "select * from flight_booking_sessions where id = $1 and user_id = $2",
      [bookingSessionId, userId]
    );
    let current = confirmed.rows[0];
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
    if (current.booking_status === "payment_canceled") {
      throw new FlightBookingError(409, "payment_canceled", "This payment session was canceled. Start payment again from the current quote.");
    }
    if (current.booking_status === "booking_in_progress") {
      const recovered = await recoverStaleBookingClaim(dbPool, {
        sessionId: bookingSessionId,
        leaseMs: bookingClaimLeaseMs,
      });
      current = recovered.session || current;
      if (current.booking_status === "booking_unknown") {
        throw new FlightBookingError(409, "booking_outcome_unknown", "The airline booking outcome is still being reconciled. Do not try again.");
      }
      if (current.booking_status === "booking_in_progress") {
        throw new FlightBookingError(409, "booking_in_progress", "This booking is already being processed. Do not submit it again.");
      }
    }

    const claimed = await dbPool.query(
      `update flight_booking_sessions
          set booking_status = 'booking_in_progress', duffel_attempted_at = now(),
              booking_claim_token = $3,
              booking_claim_expires_at = now() + ($4::bigint * interval '1 millisecond'),
              recovery_status = null, failure_code = null, failure_message = null, updated_at = now()
        where id = $1 and user_id = $2 and booking_status in ('awaiting_payment','payment_paid')
        returning *`,
      [bookingSessionId, userId, randomUUID(), bookingClaimLeaseMs]
    );
    if (!claimed.rows[0]) {
      throw new FlightBookingError(409, "booking_in_progress", "This booking is already being processed. Do not submit it again.");
    }
    return { confirmed: false, session: claimed.rows[0] };
  }

  async function updateFailure(sessionId, claimToken, status, code, message, extra = {}, expectedStatuses = ["booking_in_progress"]) {
    const updated = await dbPool.query(
      `update flight_booking_sessions set
         booking_status = $3, failure_code = $4, failure_message = $5,
         recovery_status = coalesce($6, recovery_status), stripe_refund_id = coalesce($7, stripe_refund_id),
         duffel_request_id = coalesce($8, duffel_request_id),
         booking_claim_token = case when $9 then null else booking_claim_token end,
         booking_claim_expires_at = case when $9 then null else booking_claim_expires_at end,
         updated_at = now()
       where id = $1 and booking_claim_token = $2 and booking_status = any($10::text[])
       returning *`,
      [sessionId, claimToken, status, code, message, extra.recoveryStatus || null, extra.refundId || null,
        extra.duffelRequestId || null, Boolean(extra.clearClaim), expectedStatuses]
    );
    return updated.rows[0] || null;
  }

  async function refundAfterDefinitiveFailure(session, code, message, duffelRequestId = null) {
    const marked = await dbPool.query(
      `update flight_booking_sessions
          set booking_status = 'booking_failed_refund_pending', failure_code = $2, failure_message = $3,
              recovery_status = 'refund_started', duffel_request_id = coalesce($4, duffel_request_id), updated_at = now()
        where id = $1 and booking_status = 'booking_in_progress' and booking_claim_token = $5
        returning *`,
      [session.id, code, message, duffelRequestId, session.booking_claim_token]
    );
    if (!marked.rows[0]) {
      throw new FlightBookingError(409, "booking_state_advanced", "This booking state changed before refund recovery could begin.");
    }

    let refund;
    try {
      refund = await stripe.refunds.create({
        payment_intent: session.stripe_payment_intent_id,
        reason: "requested_by_customer",
        metadata: { booking_session_id: session.id, failure_code: code },
      }, { idempotencyKey: `flight-refund-${session.id}` });
    } catch (error) {
      await updateFailure(session.id, session.booking_claim_token, "booking_failed_refund_pending", code, message, {
        recoveryStatus: "refund_failed",
        duffelRequestId,
      }, ["booking_failed_refund_pending"]);
      throw new FlightBookingError(502, "refund_pending", `${message} Stripe refund recovery requires attention.`);
    }
    const completed = refund.status === "succeeded";
    try {
      await updateFailure(session.id, session.booking_claim_token, completed ? "booking_failed_refunded" : "booking_failed_refund_pending", code, message, {
        recoveryStatus: completed ? "refunded" : (["pending", "requires_action"].includes(refund.status) ? "refund_pending" : "refund_failed"),
        refundId: refund.id,
        duffelRequestId,
        clearClaim: completed,
      }, ["booking_failed_refund_pending"]);
    } catch (_) {
      throw new FlightBookingError(502, "refund_pending", `${message} Stripe refund recovery requires attention.`);
    }
    if (!completed) {
      throw new FlightBookingError(502, "refund_pending", `${message} Stripe refund recovery requires attention.`);
    }
  }

  async function resetForSafeRetry(sessionId, claimToken, code, message) {
    const updated = await dbPool.query(
      `update flight_booking_sessions
          set booking_status = 'payment_paid', failure_code = $3, failure_message = $4,
              booking_claim_token = null, booking_claim_expires_at = null, updated_at = now()
        where id = $1 and booking_claim_token = $2
          and booking_status = 'booking_in_progress' and duffel_post_started_at is null
        returning *`,
      [sessionId, claimToken, code, message]
    );
    return updated.rows[0] || null;
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
      await resetForSafeRetry(session.id, session.booking_claim_token, "stripe_verification_failed", "Stripe payment verification could not be completed.");
      throw new FlightBookingError(502, "stripe_verification_failed", "Payment verification is temporarily unavailable. Try confirmation again.");
    }
    await dbPool.query(
      "update flight_booking_sessions set stripe_payment_status = $3, updated_at = now() where id = $1 and booking_claim_token = $2 and booking_status = 'booking_in_progress'",
      [session.id, session.booking_claim_token, intent.status]
    );
    if (intent.status !== "succeeded") {
      await dbPool.query(
        "update flight_booking_sessions set booking_status = 'awaiting_payment', booking_claim_token = null, booking_claim_expires_at = null, updated_at = now() where id = $1 and booking_claim_token = $2 and booking_status = 'booking_in_progress'",
        [session.id, session.booking_claim_token]
      );
      throw new FlightBookingError(402, "payment_not_completed", "Stripe payment has not completed.");
    }
    if (intent.amount !== pricingSessionCustomerTotalMinor(session)
        || normalizeCurrency(intent.currency) !== pricingSessionCustomerCurrency(session)) {
      await refundAfterDefinitiveFailure(session, "stripe_amount_mismatch", "The verified Stripe payment did not match the booking total.");
      throw new FlightBookingError(409, "stripe_amount_mismatch", "Payment total did not match the booking and has been refunded.");
    }

    let offer;
    let services;
    let pricing;
    let passengers;
    try {
      offer = await fetchOffer(session.duffel_offer_id);
      assertFreshOffer(offer);
      const repriced = await priceCheckout(session.payload_snapshot, offer);
      services = repriced.services;
      pricing = repriced.pricing;
      if (pricing.providerCurrency !== pricingSessionProviderCurrency(session)
          || pricing.providerTotalMinor !== pricingSessionProviderTotalMinor(session)) {
        throw new FlightBookingError(409, "price_changed", "The airline price changed before booking.");
      }
      validateTravelerTypesForOffer(session.traveler_info, offer);
      validateInternationalTravelerDocuments(session.traveler_info, offer);
      passengers = buildDuffelPassengers(session.traveler_info, session.contact_info, offer.passengers);
    } catch (error) {
      if (error.code === "duffel_timeout" || error.status >= 500) {
        await resetForSafeRetry(session.id, session.booking_claim_token, error.code || "offer_check_failed", error.message || "Offer verification failed.");
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
          currency: pricingSessionProviderCurrency(session),
          amount: minorToDecimal(pricingSessionProviderTotalMinor(session), pricingSessionProviderCurrency(session)),
        }],
        passengers,
        metadata: {
          zippi_booking_session_id: session.id,
          stripe_payment_intent_id: session.stripe_payment_intent_id,
          zippi_duffel_offer_id: session.duffel_offer_id,
          zippi_currency: pricingSessionProviderCurrency(session),
          zippi_duffel_total_minor: String(pricingSessionProviderTotalMinor(session)),
          zippi_customer_currency: pricingSessionCustomerCurrency(session),
          zippi_customer_total_minor: String(pricingSessionCustomerTotalMinor(session)),
        },
      },
    };
    if (services.length) orderPayload.data.services = services.map(({ id: serviceId, quantity }) => ({ id: serviceId, quantity }));

    const postMarker = await dbPool.query(
      `update flight_booking_sessions
          set duffel_post_started_at = now(), updated_at = now()
        where id = $1 and user_id = $2 and booking_claim_token = $3
          and booking_status = 'booking_in_progress' and duffel_post_started_at is null
        returning *`,
      [session.id, userId, session.booking_claim_token]
    );
    if (!postMarker.rows[0]) {
      throw new FlightBookingError(409, "booking_outcome_unknown", "The airline booking attempt cannot be safely retried and requires reconciliation.");
    }

    let orderResult;
    try {
      orderResult = await fetchDuffel("/air/orders", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(orderPayload),
      }, orderTimeoutMs);
    } catch (error) {
      await updateFailure(session.id, session.booking_claim_token, "booking_unknown", "duffel_timeout", "Duffel order creation timed out; outcome requires reconciliation.", {
        recoveryStatus: "manual_reconciliation_required",
        clearClaim: true,
      });
      throw new FlightBookingError(504, "booking_outcome_unknown", "The airline booking outcome is still being reconciled. Do not try again or submit another payment.");
    }

    const order = orderResult.json?.data;
    if (orderResult.response.status === 201 && order?.id) {
      const confirmation = buildConfirmation(order, session);
      const confirmed = await dbPool.query(
        `update flight_booking_sessions set
           booking_status = 'confirmed', stripe_payment_status = 'succeeded', duffel_order_id = $2,
           duffel_booking_reference = $3, duffel_request_id = $4, confirmation_snapshot = $5::jsonb,
           confirmed_at = now(), recovery_status = null, failure_code = null, failure_message = null,
           booking_claim_token = null, booking_claim_expires_at = null, updated_at = now()
         where id = $1 and booking_claim_token = $6
           and booking_status = 'booking_in_progress' and duffel_post_started_at is not null
         returning *`,
        [session.id, order.id, order.booking_reference || null, orderResult.json?.meta?.request_id || null,
          JSON.stringify(confirmation), session.booking_claim_token]
      );
      if (!confirmed.rows[0]) {
        throw new FlightBookingError(409, "booking_outcome_unknown", "The airline booking outcome changed while confirmation was being saved and requires reconciliation.");
      }
      return confirmation;
    }

    const info = duffelErrorInfo(orderResult.json);
    const definitiveFailure = isDefinitiveDuffelOrderFailureStatus(orderResult.response.status);
    if (definitiveFailure) {
      await refundAfterDefinitiveFailure(session, info.code, info.message, info.requestId);
      throw new FlightBookingError(409, info.code, `${info.message} Payment has been refunded.`);
    }

    await updateFailure(session.id, session.booking_claim_token, "booking_unknown", info.code, info.message, {
      recoveryStatus: "manual_reconciliation_required",
      duffelRequestId: info.requestId,
      clearClaim: true,
    });
    throw new FlightBookingError(502, "booking_outcome_unknown", "The airline booking outcome is still being reconciled. Do not try again or submit another payment.");
  }

  return { quoteCheckout, paymentSetup, confirmBooking, getBookingStatus };
}

module.exports = {
  FlightBookingError,
  buildConfirmation,
  buildDuffelPassengers,
  buildPricingQuote,
  calculatePricing,
  createFlightBookingService,
  currencyExponent,
  decimalToMinor,
  endpointError,
  isDefinitiveDuffelOrderFailureStatus,
  minorToDecimal,
  normalizeAvailableServices,
  requestedServiceQuantities,
  resolveSelectedServices,
  validateCheckoutPayload,
  validateInternationalTravelerDocuments,
  validateQuotePayload,
  validateTravelerTypesForOffer,
  staleBookingClaimDisposition,
};
