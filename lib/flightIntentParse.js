"use strict";

const FLIGHT_PARSE_MODEL = process.env.OPENAI_FLIGHT_PARSE_MODEL || "gpt-4o-mini";

function normalizeText(value) {
  return String(value || "").trim();
}

function normalizeQuery(value) {
  return normalizeText(value)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function parseIsoDate(value) {
  const raw = normalizeText(value);
  return /^\d{4}-\d{2}-\d{2}$/.test(raw) ? raw : null;
}

function addDays(isoDate, days) {
  const base = new Date(`${isoDate}T00:00:00Z`);
  if (Number.isNaN(base.getTime())) return null;
  base.setUTCDate(base.getUTCDate() + days);
  return base.toISOString().slice(0, 10);
}

function nextWeekdayIso(todayIso, weekdayIndex) {
  const base = new Date(`${todayIso}T00:00:00Z`);
  if (Number.isNaN(base.getTime())) return null;
  const current = base.getUTCDay();
  let delta = (weekdayIndex - current + 7) % 7;
  if (delta === 0) delta = 7;
  base.setUTCDate(base.getUTCDate() + delta);
  return base.toISOString().slice(0, 10);
}

function nextWeekendIso(todayIso) {
  return nextWeekdayIso(todayIso, 6);
}

function buildMockResponse(overrides) {
  return {
    intent: "flight",
    origin: null,
    origin_iata_hint: null,
    destination: null,
    destination_iata_hint: null,
    departure_date: null,
    return_date: null,
    trip_type: "one_way",
    adults: 1,
    confidence: 0.86,
    destination_kind: "city",
    needs_picker: false,
    picker_key: null,
    notes: null,
    ...overrides,
  };
}

function mockedFlightIntentParse(payload) {
  const query = normalizeQuery(payload.query);
  const today = parseIsoDate(payload.today) || new Date().toISOString().slice(0, 10);

  if (query === "flight from la gurdia to san fan may 10") {
    return buildMockResponse({
      origin: "LaGuardia",
      origin_iata_hint: "LGA",
      destination: "San Francisco",
      destination_iata_hint: "SFO",
      departure_date: "2026-05-10",
      confidence: 0.93,
      notes: "Corrected likely misspellings for origin and destination.",
    });
  }

  if (query === "flight to new york may 18") {
    return buildMockResponse({
      destination: "New York",
      departure_date: "2026-05-18",
      destination_kind: "ambiguous",
      needs_picker: true,
      picker_key: "new york",
      confidence: 0.9,
    });
  }

  if (query === "nyc to cali colombia next friday") {
    return buildMockResponse({
      origin: "New York City",
      destination: "Cali",
      destination_iata_hint: "CLO",
      departure_date: nextWeekdayIso(today, 5),
      confidence: 0.82,
      notes: "Destination interpreted as Cali, Colombia.",
    });
  }

  if (query === "vuelo de bogota a nueva york manana") {
    return buildMockResponse({
      origin: "Bogotá",
      origin_iata_hint: "BOG",
      destination: "New York",
      departure_date: addDays(today, 1),
      destination_kind: "ambiguous",
      needs_picker: true,
      picker_key: "new york",
      confidence: 0.9,
    });
  }

  if (query === "find me a round trip to bangkok next weekend") {
    return buildMockResponse({
      destination: "Bangkok",
      destination_iata_hint: "BKK",
      departure_date: nextWeekendIso(today),
      trip_type: "round_trip",
      return_date: null,
      confidence: 0.84,
      notes: "Round trip requested, but return date was not specified.",
    });
  }

  if (query === "flight to colombia") {
    return buildMockResponse({
      destination: "Colombia",
      destination_kind: "broad_region",
      needs_picker: true,
      picker_key: "colombia",
      confidence: 0.96,
    });
  }

  if (query === "flight to florida" || query === "vuelos a florida") {
    return buildMockResponse({
      destination: "Florida",
      destination_kind: "broad_region",
      needs_picker: true,
      picker_key: "florida",
      confidence: 0.95,
    });
  }

  return null;
}

function buildFlightIntentPrompt(payload) {
  const knownOrigin = payload.knownOriginIata ? `Known origin IATA hint: ${payload.knownOriginIata}.` : "Known origin IATA hint: none.";
  const locationCountry = payload.locationCountry ? `Location country hint: ${payload.locationCountry}.` : "Location country hint: none.";
  return [
    "Extract flight search parameters from the user's travel query.",
    "Return only structured JSON following the supplied schema.",
    "Do not invent missing origin, destination, return_date, or adults.",
    "If the query is broad or ambiguous, set needs_picker=true and picker_key when appropriate instead of forcing an airport.",
    "Use IATA codes only as hints when highly confident.",
    `Locale: ${payload.locale}.`,
    `Today: ${payload.today}.`,
    `Timezone: ${payload.timezone}.`,
    knownOrigin,
    locationCountry,
  ].join(" ");
}

function flightIntentResponseSchema() {
  return {
    type: "object",
    additionalProperties: false,
    required: [
      "intent",
      "origin",
      "origin_iata_hint",
      "destination",
      "destination_iata_hint",
      "departure_date",
      "return_date",
      "trip_type",
      "adults",
      "confidence",
      "destination_kind",
      "needs_picker",
      "picker_key",
      "notes",
    ],
    properties: {
      intent: { type: "string", enum: ["flight", "unknown"] },
      origin: { anyOf: [{ type: "string" }, { type: "null" }] },
      origin_iata_hint: { anyOf: [{ type: "string", pattern: "^[A-Z]{3}$" }, { type: "null" }] },
      destination: { anyOf: [{ type: "string" }, { type: "null" }] },
      destination_iata_hint: { anyOf: [{ type: "string", pattern: "^[A-Z]{3}$" }, { type: "null" }] },
      departure_date: { anyOf: [{ type: "string", format: "date" }, { type: "null" }] },
      return_date: { anyOf: [{ type: "string", format: "date" }, { type: "null" }] },
      trip_type: { anyOf: [{ type: "string", enum: ["one_way", "round_trip"] }, { type: "null" }] },
      adults: { anyOf: [{ type: "integer", minimum: 1, maximum: 9 }, { type: "null" }] },
      confidence: { type: "number", minimum: 0, maximum: 1 },
      destination_kind: {
        anyOf: [
          { type: "string", enum: ["airport", "city", "broad_region", "ambiguous"] },
          { type: "null" },
        ],
      },
      needs_picker: { type: "boolean" },
      picker_key: { anyOf: [{ type: "string" }, { type: "null" }] },
      notes: { anyOf: [{ type: "string" }, { type: "null" }] },
    },
  };
}

function extractStructuredOutputJson(responseJson) {
  const directText = normalizeText(responseJson?.output_text);
  if (directText) return directText;

  const outputs = Array.isArray(responseJson?.output) ? responseJson.output : [];
  for (const item of outputs) {
    const content = Array.isArray(item?.content) ? item.content : [];
    for (const part of content) {
      const text = normalizeText(part?.text);
      if (part?.type === "output_text" && text) return text;
      const refusal = normalizeText(part?.refusal);
      if (part?.type === "refusal" && refusal) {
        throw new Error(`OpenAI refusal: ${refusal}`);
      }
    }
  }
  throw new Error("OpenAI structured output missing");
}

async function parseFlightIntentWithOpenAI({ payload, apiKey, requestId, fetchImpl }) {
  const fetchFn = fetchImpl || fetch;
  const response = await fetchFn("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: FLIGHT_PARSE_MODEL,
      input: [
        { role: "system", content: buildFlightIntentPrompt(payload) },
        { role: "user", content: payload.query },
      ],
      text: {
        format: {
          type: "json_schema",
          name: "flight_intent_parse",
          strict: true,
          schema: flightIntentResponseSchema(),
        },
      },
      max_output_tokens: 500,
    }),
  });

  const responseText = await response.text();
  let responseJson;
  try {
    responseJson = responseText ? JSON.parse(responseText) : {};
  } catch (error) {
    throw new Error(`OpenAI parse response invalid for ${requestId}: ${error.message}`);
  }

  if (!response.ok) {
    const status = response.status;
    const errorMessage = normalizeText(responseJson?.error?.message) || responseText.slice(0, 180);
    throw new Error(`OpenAI parse request failed (${status}): ${errorMessage}`);
  }

  const parsedText = extractStructuredOutputJson(responseJson);
  return JSON.parse(parsedText);
}

module.exports = {
  FLIGHT_PARSE_MODEL,
  mockedFlightIntentParse,
  parseFlightIntentWithOpenAI,
};
