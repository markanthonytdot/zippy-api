"use strict";

const VALID_TRIP_TYPES = new Set(["one_way", "round_trip"]);
const VALID_DESTINATION_KINDS = new Set(["airport", "city", "broad_region", "ambiguous"]);
const PICKER_KEY_ALIASES = new Map([
  ["colombia", "colombia"],
  ["florida", "florida"],
  ["new york", "new york"],
  ["canada", "canada"],
  ["usa", "usa"],
  ["united states", "usa"],
  ["estados unidos", "usa"],
  ["mexico", "mexico"],
  ["brazil", "brazil"],
  ["brasil", "brazil"],
]);

function clampNumber(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function normalizeText(value) {
  return String(value || "").trim();
}

function normalizePickerKey(value) {
  const raw = normalizeText(value).toLowerCase();
  return PICKER_KEY_ALIASES.get(raw) || null;
}

function normalizeIataHint(value) {
  const raw = normalizeText(value).toUpperCase();
  return /^[A-Z]{3}$/.test(raw) ? raw : null;
}

function parseIsoDate(value) {
  const raw = normalizeText(value);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) return null;
  const date = new Date(`${raw}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return null;
  return raw;
}

function isPastDate(isoDate, todayIso) {
  if (!isoDate || !todayIso) return false;
  return isoDate < todayIso;
}

function inferPickerKey(data) {
  const explicit = normalizePickerKey(data.picker_key);
  if (explicit) return explicit;
  const destination = normalizeText(data.destination).toLowerCase();
  const notes = normalizeText(data.notes).toLowerCase();
  const candidates = [destination, notes];
  for (const candidate of candidates) {
    const mapped = normalizePickerKey(candidate);
    if (mapped) return mapped;
  }
  return null;
}

function validateFlightIntentRequest(body) {
  if (!body || typeof body !== "object") {
    return { ok: false, error: "Invalid JSON body" };
  }

  const query = normalizeText(body.query);
  if (!query) {
    return { ok: false, error: "query is required" };
  }

  const locale = normalizeText(body.locale) || "en";
  const today = parseIsoDate(body.today) || new Date().toISOString().slice(0, 10);
  const timezone = normalizeText(body.timezone) || "UTC";
  const knownOriginIata = normalizeIataHint(body.knownOriginIata);
  const locationCountry = normalizeText(body.locationCountry).toUpperCase() || null;
  const fallbackReason = normalizeText(body.fallback_reason) || null;

  return {
    ok: true,
    data: {
      query,
      locale,
      today,
      timezone,
      knownOriginIata,
      locationCountry,
      fallbackReason,
    },
  };
}

function validateFlightIntentResult(raw, context = {}) {
  const today = parseIsoDate(context.today) || new Date().toISOString().slice(0, 10);
  const source = raw && typeof raw === "object" ? raw : {};

  const intent = normalizeText(source.intent) === "flight" ? "flight" : "unknown";
  const origin = normalizeText(source.origin) || null;
  const destination = normalizeText(source.destination) || null;
  let originIataHint = normalizeIataHint(source.origin_iata_hint);
  let destinationIataHint = normalizeIataHint(source.destination_iata_hint);
  let departureDate = parseIsoDate(source.departure_date);
  let returnDate = parseIsoDate(source.return_date);
  const tripType = VALID_TRIP_TYPES.has(source.trip_type) ? source.trip_type : "one_way";
  const adults = clampNumber(source.adults, 1, 9, 1);
  const confidence = clampNumber(source.confidence, 0, 1, 0);
  let destinationKind = VALID_DESTINATION_KINDS.has(source.destination_kind)
    ? source.destination_kind
    : (destinationIataHint ? "airport" : destination ? "city" : null);
  let needsPicker = source.needs_picker === true;
  let pickerKey = inferPickerKey(source);
  const notes = normalizeText(source.notes) || null;

  const issues = [];

  if (departureDate && isPastDate(departureDate, today)) {
    issues.push("departure_in_past");
    departureDate = null;
  }
  if (returnDate && isPastDate(returnDate, today)) {
    issues.push("return_in_past");
    returnDate = null;
  }
  if (departureDate && returnDate && returnDate <= departureDate) {
    issues.push("return_not_after_departure");
    returnDate = null;
  }
  if (originIataHint && destinationIataHint && originIataHint === destinationIataHint) {
    issues.push("same_iata_hint");
    destinationIataHint = null;
  }

  if (destinationKind === "broad_region" || destinationKind === "ambiguous" || pickerKey) {
    needsPicker = true;
  }
  if (needsPicker && !pickerKey && destination) {
    pickerKey = normalizePickerKey(destination);
  }
  if (needsPicker && pickerKey && destinationKind == null) {
    destinationKind = "broad_region";
  }

  return {
    valid: true,
    issues,
    data: {
      intent,
      origin,
      origin_iata_hint: originIataHint,
      destination,
      destination_iata_hint: destinationIataHint,
      departure_date: departureDate,
      return_date: returnDate,
      trip_type: tripType,
      adults,
      confidence,
      destination_kind: destinationKind,
      needs_picker: needsPicker,
      picker_key: pickerKey,
      notes,
    },
  };
}

module.exports = {
  validateFlightIntentRequest,
  validateFlightIntentResult,
};
