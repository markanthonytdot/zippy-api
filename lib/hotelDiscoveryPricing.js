const { decimalToMinorExact } = require("./currencyAmount");
const { SUPPORTED_CUSTOMER_CURRENCIES } = require("./pricingConfig");

const SELECTION_KEYS = ["hotelId", "searchResultId", "rateId", "checkIn", "checkOut", "adults", "rooms", "currency"];
const ID = /^[A-Za-z0-9._:-]{1,120}$/;
const CURRENCY = /^[A-Z]{3}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;

function matchesEntire(pattern, value) {
  return typeof value === "string" && pattern.exec(value)?.[0] === value;
}

function dateOnly(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const ms = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 10) === value ? ms : null;
}

function timestamp(value) {
  if (!matchesEntire(TIMESTAMP, value)) return null;
  if (dateOnly(value.slice(0, 10)) === null) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function validateDiscoverySelection(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)
      || Object.keys(raw).some((key) => !SELECTION_KEYS.includes(key))) return null;
  if (![raw.hotelId, raw.searchResultId, raw.rateId].every((id) => matchesEntire(ID, id))) return null;
  const checkIn = dateOnly(raw.checkIn);
  const checkOut = dateOnly(raw.checkOut);
  if (checkIn === null || checkOut === null || checkOut <= checkIn || checkOut - checkIn > 30 * 86400000) return null;
  if (!Number.isInteger(raw.adults) || raw.adults < 1 || raw.adults > 9 || raw.rooms !== 1) return null;
  if (!matchesEntire(CURRENCY, raw.currency)) return null;
  return Object.fromEntries(SELECTION_KEYS.map((key) => [key, raw[key]]));
}

function money(amount, currency) {
  // Supplier decimal strings only. JSON numbers may already have lost precision.
  if (typeof amount !== "string" || !matchesEntire(CURRENCY, currency)) return null;
  try { return { currency, amountMinor: decimalToMinorExact(amount, currency) }; }
  catch (_) { return null; }
}

function emptyProjection(selection, now, status = "incomplete", reasons = []) {
  return {
    version: 1,
    status,
    reasons,
    selection: { ...selection },
    customerCurrency: selection.currency,
    customerTotalMinor: null,
    rateTotal: null,
    dueAtAccommodation: null,
    taxes: "unknown",
    mandatoryFees: "unknown",
    propertyCharges: "unknown",
    source: "duffel_fetch_all_rates",
    pricedAt: new Date(now).toISOString(),
    expiresAt: null,
  };
}

/**
 * Only a fresh, unmodified Duffel fetch_all_rates response is accepted here.
 * Rate total = base + tax + fee, for all nights and guests. Mandatory property
 * charges are EXCLUDED and live in due_at_accommodation_amount (null = unknown).
 * https://duffel.com/docs/api/v2/search-result/schema
 * No search-card fallback, quote creation, FX, markup, or display rounding.
 */
function projectHotelDiscoveryPrice(result, selection, { now = Date.now(), enabledCurrencies = SUPPORTED_CUSTOMER_CURRENCIES } = {}) {
  const output = emptyProjection(selection, now);
  if (!SUPPORTED_CUSTOMER_CURRENCIES.includes(selection.currency) || !enabledCurrencies.includes(selection.currency)) {
    return { ...output, status: "incompatible_currency", reasons: ["unsupported_customer_currency"] };
  }

  const guests = result?.guests;
  if (result?.id !== selection.searchResultId || result?.accommodation?.id !== selection.hotelId
      || result?.check_in_date !== selection.checkIn || result?.check_out_date !== selection.checkOut
      || result?.rooms !== selection.rooms || !Array.isArray(guests) || guests.length !== selection.adults
      || !guests.every((guest) => guest?.type === "adult")) {
    return { ...output, status: "identity_mismatch", reasons: ["search_context_mismatch"] };
  }
  const rooms = Array.isArray(result.accommodation.rooms) ? result.accommodation.rooms : [];
  const rates = rooms.flatMap((room) => Array.isArray(room?.rates) ? room.rates : []);
  const matches = rates.filter((rate) => rate?.id === selection.rateId);
  if (matches.length !== 1) {
    return { ...output, status: "identity_mismatch", reasons: [matches.length ? "ambiguous_rate_identity" : "rate_not_in_search_result"] };
  }
  const rate = matches[0];
  const searchExpiry = timestamp(result.expires_at);
  const rateExpiry = timestamp(rate.expires_at);
  if (searchExpiry === null || rateExpiry === null) {
    return { ...output, status: "refresh_needed", reasons: ["provider_expiry_unknown"] };
  }
  const expiresAt = Math.min(searchExpiry, rateExpiry);
  output.expiresAt = new Date(expiresAt).toISOString();
  if (expiresAt <= now) {
    return { ...output, status: "refresh_needed", reasons: ["provider_price_expired"] };
  }

  output.rateTotal = money(rate.total_amount, rate.total_currency);
  output.dueAtAccommodation = money(rate.due_at_accommodation_amount, rate.due_at_accommodation_currency);
  if (output.dueAtAccommodation) output.propertyCharges = "known_additional";

  if ((typeof rate.total_currency === "string" && CURRENCY.test(rate.total_currency) && rate.total_currency !== selection.currency)
      || (typeof rate.due_at_accommodation_currency === "string" && CURRENCY.test(rate.due_at_accommodation_currency)
        && rate.due_at_accommodation_currency !== selection.currency)) {
    return { ...output, status: "incompatible_currency", reasons: ["provider_currency_mismatch"] };
  }

  if ([rate.base_currency, rate.tax_currency, rate.fee_currency].some((code) =>
    typeof code === "string" && CURRENCY.test(code) && code !== selection.currency)) {
    return { ...output, status: "incompatible_currency", reasons: ["provider_currency_mismatch"] };
  }
  const base = money(rate.base_amount, rate.base_currency);
  const tax = money(rate.tax_amount, rate.tax_currency);
  const fee = money(rate.fee_amount, rate.fee_currency);
  if (!output.rateTotal || output.rateTotal.amountMinor <= 0) output.reasons.push("rate_total_unknown");
  if (!base || !tax || !fee) {
    output.reasons.push("tax_fee_breakdown_unknown");
  } else if (output.rateTotal
      && BigInt(base.amountMinor) + BigInt(tax.amountMinor) + BigInt(fee.amountMinor) === BigInt(output.rateTotal.amountMinor)) {
    output.taxes = "known_included";
    output.mandatoryFees = "known_included";
  } else {
    output.reasons.push("rate_breakdown_inconsistent");
  }
  if (!output.dueAtAccommodation) output.reasons.push("property_charges_unknown");
  if (output.reasons.length) return output;

  const total = BigInt(output.rateTotal.amountMinor) + BigInt(output.dueAtAccommodation.amountMinor);
  if (total > BigInt(Number.MAX_SAFE_INTEGER)) {
    return { ...output, reasons: ["customer_total_overflow"] };
  }
  return { ...output, status: "authoritative", customerTotalMinor: Number(total) };
}

function createHotelDiscoveryPricingHandler({ fetchRates, getEnabledCurrencies, now = Date.now }) {
  return async function hotelDiscoveryPricing(req, res) {
    const body = req.body?.data && typeof req.body.data === "object" ? req.body.data : req.body;
    const selection = validateDiscoverySelection(body?.discoveryPricing);
    if (!selection) return res.status(400).json({ ok: false, error: "Invalid hotel discovery pricing request." });
    // Currency failure never changes the requested currency or performs FX.
    let enabledCurrencies;
    try {
      enabledCurrencies = await getEnabledCurrencies();
      if (!Array.isArray(enabledCurrencies)) throw new Error("Invalid currency configuration");
    }
    catch (_) {
      return res.json({ ok: true, discoveryPrice: emptyProjection(selection, now(), "unavailable", ["currency_configuration_unavailable"]) });
    }
    if (!SUPPORTED_CUSTOMER_CURRENCIES.includes(selection.currency) || !enabledCurrencies.includes(selection.currency)) {
      return res.json({ ok: true, discoveryPrice: emptyProjection(selection, now(), "incompatible_currency", ["unsupported_customer_currency"]) });
    }
    try {
      // Deliberately bypass legacy hotel/date cache: it neither binds the latest
      // search-result/rate identity nor records original price expiry/coverage.
      const fetched = await fetchRates({ searchResultId: selection.searchResultId, requestId: req.requestId });
      if (!fetched?.ok || !fetched.result) {
        const expired = [404, 410, 422].includes(fetched?.providerStatus ?? fetched?.status);
        return res.json({ ok: true, discoveryPrice: emptyProjection(selection, now(), expired ? "refresh_needed" : "unavailable",
          [expired ? "provider_search_needs_refresh" : "provider_pricing_unavailable"]) });
      }
      return res.json({ ok: true, discoveryPrice: projectHotelDiscoveryPrice(fetched.result, selection, { now: now(), enabledCurrencies }) });
    } catch (_) {
      return res.json({ ok: true, discoveryPrice: emptyProjection(selection, now(), "unavailable", ["provider_pricing_unavailable"]) });
    }
  };
}

module.exports = { validateDiscoverySelection, projectHotelDiscoveryPrice, createHotelDiscoveryPricingHandler };
