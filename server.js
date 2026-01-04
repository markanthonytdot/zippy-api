const express = require("express");
const helmet = require("helmet");
const { randomUUID } = require("crypto");
const { Pool } = require("pg");
const app = express();

app.set("trust proxy", true);
app.use(helmet());
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));
// ---------------------------------------------
// Simple in-memory cache + rate limit helpers
// ---------------------------------------------

function nowMs() {
  return Date.now();
}

// basic TTL cache
function makeTtlCache() {
  const map = new Map(); // key -> { exp, value }
  return {
    get(key) {
      const hit = map.get(key);
      if (!hit) return null;
      if (hit.exp <= nowMs()) {
        map.delete(key);
        return null;
      }
      return hit.value;
    },
    set(key, value, ttlMs) {
      map.set(key, { exp: nowMs() + ttlMs, value });
    },
    _size() {
      return map.size;
    },
  };
}

// basic fixed-window rate limit per user
function makeFixedWindowLimiter({ windowMs, max }) {
  const map = new Map(); // key -> { start, count }
  return {
    allow(key) {
      const t = nowMs();
      const cur = map.get(key);
      if (!cur || t - cur.start >= windowMs) {
        map.set(key, { start: t, count: 1 });
        return { ok: true, remaining: max - 1 };
      }
      if (cur.count >= max) {
        return { ok: false, remaining: 0 };
      }
      cur.count += 1;
      return { ok: true, remaining: max - cur.count };
    },
  };
}

function makePrunableFixedWindowLimiter({ windowMs, max, pruneIntervalMs = 60 * 1000 }) {
  const map = new Map(); // key -> { start, count }
  let lastPrune = 0;
  function prune() {
    const t = nowMs();
    if (t - lastPrune < pruneIntervalMs) return;
    lastPrune = t;
    for (const [key, val] of map) {
      if (t - val.start >= windowMs) {
        map.delete(key);
      }
    }
  }
  return {
    allow(key) {
      if (max < 0) return { ok: true, remaining: Infinity };
      const t = nowMs();
      prune();
      const cur = map.get(key);
      if (!cur || t - cur.start >= windowMs) {
        map.set(key, { start: t, count: 1 });
        return { ok: true, remaining: max - 1 };
      }
      if (cur.count >= max) {
        return { ok: false, remaining: 0 };
      }
      cur.count += 1;
      return { ok: true, remaining: max - cur.count };
    },
  };
}

function getRequestIp(req) {
  const xfwd = String(req.headers["x-forwarded-for"] || "");
  const first = xfwd.split(",")[0].trim();
  return String(req.ip || first || req.connection?.remoteAddress || "").trim() || "unknown";
}

function getRateLimitKey(req, userId) {
  const uid = String(userId || req.userId || "").trim();
  if (uid) return `uid:${uid}`;
  return `ip:${getRequestIp(req)}`;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

// caches
const placesDetailsCache = makeTtlCache(); // key = placeId
const placesDetailsPhotosCache = makeTtlCache(); // key = placeId:max
const etaCache = makeTtlCache(); // key = rounded origin/dest + mode/traffic
const hotelPhotoCache = makeTtlCache(); // key = hotelId or name+city
const hotelDetailsCache = makeTtlCache(); // key = hotelId
const hotelPhotoRefCache = makeTtlCache(); // key = hotelId

const HOTEL_PHOTO_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const HOTEL_PHOTO_MAX_WIDTH = 900;
const HOTEL_PHOTO_REF_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const HOTEL_DETAILS_TTL_MS = 24 * 60 * 60 * 1000;
const HOTEL_PHOTO_REF_NULL_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// limiters (tune later)
const placesDetailsLimiter = makeFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: Number(process.env.PLACES_DETAILS_RPM || 30), // per user per minute
});
const placesDetailsPhotosLimiter = makeFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: Number(process.env.PLACES_DETAILS_PHOTOS_RPM || 20), // per user per minute
});
const placesDetailsPhotosDailyCounters = new Map(); // key: userId:YYYY-MM-DD -> count
// HOTELS_RPM, HOTELS_HOURLY, HOTELS_DAILY
const hotelsMinuteLimiter = makeFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("HOTELS_RPM", 10), // per user per minute
});
const hotelsHourlyCounters = new Map(); // key: userId:YYYY-MM-DDTHH -> count
const hotelsDailyCounters = new Map(); // key: userId:YYYY-MM-DD -> count
const etaMinuteLimiterFree = makeFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("ETA_RPM_FREE", 1),
});
const etaMinuteLimiterPaid = makeFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("ETA_RPM_PAID", 10),
});
const globalLimiter = makePrunableFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("GLOBAL_RPM", 120),
});
const placesPhotoRouteLimiter = makePrunableFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("PLACES_PHOTO_ROUTE_RPM", 30),
});
const placesDetailsPhotosRouteLimiter = makePrunableFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("PLACES_DETAILS_PHOTOS_ROUTE_RPM", 30),
});
const etaRouteLimiter = makePrunableFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("ETA_ROUTE_RPM", 20),
});
const hotelsRouteLimiter = makePrunableFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("HOTELS_ROUTE_RPM", 20),
});
const authAppleLimiter = makePrunableFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("AUTH_APPLE_RPM", 10),
});
const meSavedLimiter = makePrunableFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("SAVED_RPM", 60),
});
const adminInitLimiter = makePrunableFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: getEnvInt("ADMIN_INIT_RPM", 5),
});

// Google key (server-only)
const GOOGLE_PLACES_API_KEY = process.env.GOOGLE_PLACES_API_KEY || "";
// Amadeus config (server-only)
const AMADEUS_CLIENT_ID = process.env.AMADEUS_CLIENT_ID || "";
const AMADEUS_CLIENT_SECRET = process.env.AMADEUS_CLIENT_SECRET || "";
const AMADEUS_BASE_URL = process.env.AMADEUS_BASE_URL || "https://test.api.amadeus.com";

// ---------------------------------------------
// Auth config
// ---------------------------------------------
const AUTH_MODE = String(process.env.AUTH_MODE || "dev").toLowerCase();
const JWT_SECRET = process.env.JWT_SECRET || "";
const JWT_ISSUER = process.env.JWT_ISSUER || "zippy-api";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "zippy-ios";
const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID || "";
const APPLE_ISSUER = "https://appleid.apple.com";
const APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys";

// jose lazy loader (works in CommonJS)
let josePromise = null;
function getJose() {
  if (!josePromise) {
    josePromise = import("jose");
  }
  return josePromise;
}

// cache Apple JWKS
let appleJwks = null;
async function getAppleJwks() {
  if (!appleJwks) {
    const { createRemoteJWKSet } = await getJose();
    appleJwks = createRemoteJWKSet(new URL(APPLE_JWKS_URL));
  }
  return appleJwks;
}

// sign our own Zippy JWT (HS256)
async function signZippyToken(subject) {
  if (!JWT_SECRET) return null;
  const { SignJWT } = await getJose();
  const encoder = new TextEncoder();

  return new SignJWT({ uid: subject })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(subject)
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("30d")
    .sign(encoder.encode(JWT_SECRET));
}

async function hydrateUserIdFromAuth(req) {
  if (req.userId) return;

  const auth = String(req.headers.authorization || "");
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m && JWT_SECRET) {
    const token = m[1].trim();
    try {
      const { jwtVerify } = await getJose();
      const encoder = new TextEncoder();
      const { payload } = await jwtVerify(token, encoder.encode(JWT_SECRET), {
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });

      const sub = String(payload?.sub || "").trim();
      if (sub) {
        req.userId = sub;
        req.userIdVerified = true;
        return;
      }
    } catch (_) {
      // ignore auth errors here; real auth happens in requireUserId
    }
  }

  const fallbackUserId = String(req.headers["x-user-id"] || "").trim();
  if (fallbackUserId) {
    req.userId = fallbackUserId;
    req.userIdVerified = false;
  }
}

function rateLimitMiddleware(limiter, label) {
  return (req, res, next) => {
    const key = getRateLimitKey(req);
    const lim = limiter.allow(`${label}:${key}`);
    if (!lim.ok) {
      return res.status(429).json({ ok: false, error: "Rate limit exceeded" });
    }
    return next();
  };
}

app.use(async (req, res, next) => {
  await hydrateUserIdFromAuth(req);
  next();
});

app.use((req, res, next) => {
  if (req.path === "/health") return next();
  const key = getRateLimitKey(req);
  const lim = globalLimiter.allow(`global:${key}`);
  if (!lim.ok) {
    return res.status(429).json({ ok: false, error: "Rate limit exceeded" });
  }
  return next();
});

app.use("/v1/places/photo", rateLimitMiddleware(placesPhotoRouteLimiter, "placesPhoto"));
app.use("/v1/places/details/photos", rateLimitMiddleware(placesDetailsPhotosRouteLimiter, "placesDetailsPhotos"));
app.use("/v1/places/eta", rateLimitMiddleware(etaRouteLimiter, "eta"));
app.use("/v1/hotels", rateLimitMiddleware(hotelsRouteLimiter, "hotels"));
app.use("/auth/apple", rateLimitMiddleware(authAppleLimiter, "authApple"));
app.use("/me/saved", rateLimitMiddleware(meSavedLimiter, "meSaved"));
app.use("/admin/init", rateLimitMiddleware(adminInitLimiter, "adminInit"));

// ---------------------------------------------
// Basic health
// ---------------------------------------------
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "zippy-api",
    authMode: String(process.env.AUTH_MODE || "dev"),
    hasJwtSecret: !!process.env.JWT_SECRET,
    jwtIssuer: String(process.env.JWT_ISSUER || ""),
    jwtAudience: String(process.env.JWT_AUDIENCE || ""),
    hasAmadeusId: !!process.env.AMADEUS_CLIENT_ID,
    hasAmadeusSecret: !!process.env.AMADEUS_CLIENT_SECRET,
  });
});
// ---------------------------------------------
// Version (deploy test)
// ---------------------------------------------
app.get("/version", (req, res) => {
  res.json({
    ok: true,
    service: "zippy-api",
    ts: new Date().toISOString(),
  });
});


// ---------------------------------------------
// Database pool
// ---------------------------------------------
const dbPool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
  : null;

// ---------------------------------------------
// DB health
// ---------------------------------------------
app.get("/health/db", async (req, res) => {
  if (!dbPool) {
    return res.status(500).json({ ok: false, error: "DATABASE_URL not set" });
  }

  try {
    await dbPool.query("select 1");
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------------------------------------------
// Root route
// ---------------------------------------------
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "zippy-api",
    routes: ["/health", "/health/db"],
  });
});

// ---------------------------------------------
// Hotels abuse protection
// ---------------------------------------------
app.use("/v1/hotels", async (req, res, next) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;

  const limiterId = getRateLimitKey(req, userId);
  const lim = hotelsMinuteLimiter.allow(`hotels:${limiterId}`);
  if (!lim.ok) return res.status(429).json({ ok: false, error: "Hotel rate limit exceeded. Try again shortly." });

  const q = enforceHotelsHourlyDaily(limiterId);
  if (!q.ok) return res.status(q.status).json({ ok: false, error: q.error });

  console.log(
    "[Hotels LIMIT]",
    "userId=" + userId,
    "path=" + req.path,
    "hour=" + q.hourCount + "/" + q.hourlyLimit,
    "day=" + q.dayCount + "/" + q.dailyLimit
  );
  next();
});

// ---------------------------------------------
// Hotels ping (test route)
// ---------------------------------------------
app.get("/v1/hotels/ping", (req, res) => {
  res.json({ ok: true, hotelLimiter: true });
});

// ---------------------------------------------
// Hotels Search (Amadeus)
// POST /v1/hotels/search
// ---------------------------------------------
app.post("/v1/hotels/search", async (req, res) => {
  const userId = String(req.userId || "unknown");
  const requestId = randomUUID();

  if (!AMADEUS_CLIENT_ID || !AMADEUS_CLIENT_SECRET) {
    return res.status(500).json({ ok: false, error: "AMADEUS creds missing" });
  }

  const body = req.body || {};
  const city = String(body.city || "").trim();
  if (city && city.length > 200) {
    return res.status(400).json({ ok: false, error: "Invalid city" });
  }

  const hasLatField = body.lat !== undefined || body.lng !== undefined;
  const latInput = Number(body.lat);
  const lngInput = Number(body.lng);

  if (hasLatField) {
    if (!Number.isFinite(latInput) || !Number.isFinite(lngInput)) {
      return res.status(400).json({ ok: false, error: "Invalid lat/lng" });
    }
    if (latInput < -90 || latInput > 90 || lngInput < -180 || lngInput > 180) {
      return res.status(400).json({ ok: false, error: "Invalid lat/lng bounds" });
    }
  }

  if (!city && !hasLatField) {
    return res.status(400).json({ ok: false, error: "Missing city or lat/lng" });
  }

  const checkIn = String(body.checkIn || "").trim();
  if (!checkIn) {
    return res.status(400).json({ ok: false, error: "Missing checkIn" });
  }

  const nightsRaw = Number(body.nights);
  if (!Number.isFinite(nightsRaw)) {
    return res.status(400).json({ ok: false, error: "Missing nights" });
  }
  const nights = Math.round(nightsRaw);
  if (nights <= 0 || nights > 30) {
    return res.status(400).json({ ok: false, error: "Invalid nights" });
  }

  const checkOut = addNightsToDate(checkIn, nights);
  if (!checkOut) {
    return res.status(400).json({ ok: false, error: "Invalid checkIn" });
  }

  let adults = Number(body.adults);
  if (!Number.isFinite(adults)) adults = 1;
  adults = Math.round(adults);
  if (adults <= 0) adults = 1;
  if (adults > 9) adults = 9;

  let radiusKm = Number(body.radiusKm);
  if (!Number.isFinite(radiusKm)) radiusKm = 15;
  if (radiusKm <= 0) radiusKm = 15;
  if (radiusKm > 50) radiusKm = 50;

  const rawMax = body.max;
  let max = Number(rawMax);
  if (!Number.isFinite(max)) max = 12;
  max = Math.round(max);
  if (max <= 0) max = 12;
  if (max > 50) max = 50;

  let searchLat = latInput;
  let searchLng = lngInput;
  if (!hasLatField) {
    if (!GOOGLE_PLACES_API_KEY) {
      return res.status(500).json({ ok: false, error: "GOOGLE_PLACES_API_KEY not set" });
    }
    const geocoded = await geocodeCityToLatLng(city);
    if (!geocoded) {
      return res.status(400).json({ ok: false, error: "Unable to geocode city" });
    }
    searchLat = geocoded.lat;
    searchLng = geocoded.lng;
  }

  const tokenResult = await fetchAmadeusToken(requestId);
  if (!tokenResult.ok) {
    return res.status(tokenResult.status).json({ ok: false, error: tokenResult.error });
  }

  const hotelsUrl = new URL(`${AMADEUS_BASE_URL}/v1/reference-data/locations/hotels/by-geocode`);
  setOptionalQueryParam(hotelsUrl, "latitude", searchLat);
  setOptionalQueryParam(hotelsUrl, "longitude", searchLng);
  setOptionalQueryParam(hotelsUrl, "radius", radiusKm);
  setOptionalQueryParam(hotelsUrl, "radiusUnit", "KM");
  setOptionalQueryParam(hotelsUrl, "hotelSource", "ALL");

  console.log("[Hotels LIST]", "requestId=" + requestId, "lat=" + searchLat, "lng=" + searchLng);
  if (shouldLogHotelsUrl()) {
    console.log("[Hotels LIST]", "requestId=" + requestId, "url=" + hotelsUrl.toString());
  }

  const tokenHost = getUrlHost(getAmadeusTokenUrl());
  const hotelsHost = hotelsUrl.host;
  const tokenPrefix = tokenResult.token.slice(0, 12);
  console.log(
    "[Hotels AMADEUS]",
    "requestId=" + requestId,
    "tokenHost=" + tokenHost,
    "hotelsHost=" + hotelsHost,
    "tokenPrefix=" + tokenPrefix,
    "tokenLen=" + tokenResult.token.length
  );

  let hotelsRes;
  let hotelsJson = {};
  let hotelsText = "";
  try {
    hotelsRes = await fetchWithTimeout(hotelsUrl.toString(), {
      headers: { Authorization: `Bearer ${tokenResult.token}` },
    });
    hotelsText = await hotelsRes.text().catch(() => "");
    hotelsJson = safeJsonParse(hotelsText);
  } catch (e) {
    console.log("[Hotels LIST]", "requestId=" + requestId, "userId=" + userId, "status=ERR", "count=0");
    return res.status(502).json({ ok: false, error: "Amadeus hotels fetch failed" });
  }

  const hotelsData = Array.isArray(hotelsJson?.data) ? hotelsJson.data : [];
  const hotelItems = hotelsData.filter((item) => item && item.hotelId).slice(0, max);
  const hotelIds = [];
  const seenHotelIds = new Set();
  for (const item of hotelItems) {
    const id = String(item?.hotelId || "").trim();
    if (id && !seenHotelIds.has(id)) {
      seenHotelIds.add(id);
      hotelIds.push(id);
    }
  }

  console.log(
    "[Hotels LIST]",
    "requestId=" + requestId,
    "userId=" + userId,
    "status=" + hotelsRes.status,
    "count=" + hotelIds.length
  );

  if (!hotelsRes.ok) {
    const hostPath = `${hotelsUrl.host}${hotelsUrl.pathname}`;
    const bodySnippet = truncateText(hotelsText, 500);
    if (shouldLogHotelsUrl()) {
      console.log(
        "[Hotels LIST]",
        "requestId=" + requestId,
        "url=" + hotelsUrl.toString(),
        "hostPath=" + hostPath,
        "status=" + hotelsRes.status,
        "body=" + bodySnippet
      );
    } else {
      console.log(
        "[Hotels LIST]",
        "requestId=" + requestId,
        "hostPath=" + hostPath,
        "status=" + hotelsRes.status,
        "body=" + bodySnippet
      );
    }
    return res.status(502).json({
      ok: false,
      error: "Amadeus hotels fetch failed",
      hint: `step=hotels url=${hotelsUrl.toString()} status=${hotelsRes.status} body=${bodySnippet}`,
    });
  }

  if (hotelIds.length === 0) {
    console.log("[Hotels OFFERS]", "requestId=" + requestId, "userId=" + userId, "status=SKIP", "count=0");
    return res.json({
      ok: true,
      cached: false,
      query: { city: city || null, lat: searchLat, lng: searchLng, checkIn, nights, adults, radiusKm, max },
      items: [],
    });
  }

  const hotelsById = new Map();
  for (const item of hotelItems) {
    const id = String(item?.hotelId || "").trim();
    if (id) hotelsById.set(id, item);
  }
  async function fetchOffersBatch(batchIds, batchLabel) {
    const offersUrl = new URL(`${AMADEUS_BASE_URL}/v3/shopping/hotel-offers`);
    offersUrl.searchParams.set("hotelIds", batchIds.join(","));
    offersUrl.searchParams.set("checkInDate", checkIn);
    offersUrl.searchParams.set("checkOutDate", checkOut);
    offersUrl.searchParams.set("adults", String(adults));
    offersUrl.searchParams.set("roomQuantity", "1");
    offersUrl.searchParams.set("paymentPolicy", "NONE");
    offersUrl.searchParams.set("bestRateOnly", "true");

    let offersRes;
    let offersJson = {};
    let offersText = "";
    try {
      offersRes = await fetchWithTimeout(offersUrl.toString(), {
        headers: { Authorization: `Bearer ${tokenResult.token}` },
      });
      offersText = await offersRes.text().catch(() => "");
      offersJson = safeJsonParse(offersText);
    } catch (e) {
      console.log(
        "[Hotels OFFERS]",
        "requestId=" + requestId,
        "userId=" + userId,
        "status=ERR",
        "count=0",
        "batch=" + batchLabel
      );
      return { ok: false, status: 502, error: "Amadeus offers fetch failed" };
    }

    const offersData = Array.isArray(offersJson?.data) ? offersJson.data : [];
    console.log(
      "[Hotels OFFERS]",
      "requestId=" + requestId,
      "userId=" + userId,
      "status=" + offersRes.status,
      "count=" + offersData.length,
      "batch=" + batchLabel,
      "ids=" + batchIds.length
    );

    if (!offersRes.ok) {
      const hostPath = `${offersUrl.host}${offersUrl.pathname}`;
      const bodySnippet = truncateText(offersText, 500);
      console.log(
        "[Hotels OFFERS]",
        "requestId=" + requestId,
        "hostPath=" + hostPath,
        "status=" + offersRes.status,
        "batch=" + batchLabel,
        "body=" + bodySnippet
      );
      return {
        ok: false,
        status: 502,
        error: "Amadeus offers fetch failed",
        hint: `step=offers status=${offersRes.status} body=${bodySnippet}`,
      };
    }

    return { ok: true, offersData };
  }

  let offersData = [];
  let offersError = null;
  const offersAttempt = await fetchOffersBatch(hotelIds, "all");
  if (offersAttempt.ok) {
    offersData = offersAttempt.offersData;
  } else if (hotelIds.length > 10) {
    console.log(
      "[Hotels OFFERS]",
      "requestId=" + requestId,
      "userId=" + userId,
      "status=RETRY",
      "reason=batch",
      "ids=" + hotelIds.length
    );
    const batches = chunkArray(hotelIds, 10);
    for (let i = 0; i < batches.length; i += 1) {
      const batch = batches[i];
      const batchLabel = `batch=${i + 1}/${batches.length}`;
      const result = await fetchOffersBatch(batch, batchLabel);
      if (result.ok) {
        offersData = offersData.concat(result.offersData);
      } else if (!offersError) {
        offersError = result;
      }
    }
    if (offersData.length === 0) {
      const error = offersError?.error || offersAttempt.error || "Amadeus offers fetch failed";
      const hint = offersError?.hint || offersAttempt.hint;
      return res.status(502).json({ ok: false, error, hint });
    }
  } else {
    return res.status(502).json({
      ok: false,
      error: offersAttempt.error || "Amadeus offers fetch failed",
      hint: offersAttempt.hint,
    });
  }

  const offersReturnedCount = offersData.length;
  const offersByHotelId = new Map();
  for (const entry of offersData) {
    const hotel = entry?.hotel || {};
    const hotelId = String(hotel.hotelId || entry?.hotelId || "").trim();
    if (!hotelId) continue;
    const bestOffer = pickBestOfferDetails(entry?.offers);
    if (!bestOffer) continue;
    const price = bestOffer.price;
    const existing = offersByHotelId.get(hotelId);
    if (!existing) {
      offersByHotelId.set(hotelId, { entry, bestOffer, price });
      continue;
    }
    if (price && !existing.price) {
      offersByHotelId.set(hotelId, { entry, bestOffer, price });
      continue;
    }
    if (price && existing.price) {
      const newTotal = price.totalNum;
      const oldTotal = existing.price.totalNum;
      const sameCurrency = !price.currency || !existing.price.currency || price.currency === existing.price.currency;
      if (sameCurrency && Number.isFinite(newTotal) && Number.isFinite(oldTotal) && newTotal < oldTotal) {
        offersByHotelId.set(hotelId, { entry, bestOffer, price });
      } else if (!Number.isFinite(oldTotal) && Number.isFinite(newTotal)) {
        offersByHotelId.set(hotelId, { entry, bestOffer, price });
      }
    }
  }

  const outputMax = Math.min(max, 50);
  const items = [];
  for (const hotelId of hotelIds) {
    const offer = offersByHotelId.get(hotelId);
    if (!offer) continue;
    const entry = offer.entry || {};
    const hotel = entry?.hotel || {};
    const bestOffer = offer.bestOffer?.offer || null;
    const fallback = hotelsById.get(hotelId) || {};
    const geo = hotel.geoCode || fallback.geoCode || {};
    const lat = Number(geo.latitude ?? geo.lat);
    const lng = Number(geo.longitude ?? geo.lng);
    const name = String(hotel.name || fallback.name || "").trim();
    const address = formatAmadeusAddress(hotel.address || fallback.address);
    const rating = parseAmadeusRating(hotel.rating || hotel.hotelRating || fallback.rating);
    const offerPrice = offer.price || null;
    const price = offerPrice ? { total: offerPrice.total, currency: offerPrice.currency } : null;
    const roomType = pickOfferRoomType(bestOffer);
    const roomDescription = pickOfferRoomDescription(bestOffer);
    const bedType = pickOfferBedType(bestOffer);
    const boardType = pickOfferBoardType(bestOffer);
    const paymentType = pickOfferPaymentType(bestOffer);
    const cancellationInfo = pickOfferCancellation(bestOffer);
    const offerCheckIn = pickOfferCheckInDate(bestOffer, checkIn);
    const offerCheckOut = pickOfferCheckOutDate(bestOffer, checkOut, offerCheckIn, nights);
    const offerPayload = bestOffer
      ? {
          id: pickOfferId(bestOffer),
          checkInDate: offerCheckIn,
          checkOutDate: offerCheckOut,
          adults,
          roomType,
          roomDescription,
          bedType,
          boardType,
          paymentType,
          refundable: cancellationInfo.refundable,
          cancellation: cancellationInfo.cancellation,
          price: offerPrice
            ? {
                total: offerPrice.total,
                base: offerPrice.base,
                taxes: offerPrice.taxes,
                currency: offerPrice.currency,
              }
            : { total: null, base: null, taxes: null, currency: null },
          raw: buildOfferRawDebug(bestOffer),
        }
      : null;

    cacheHotelDetails(hotelId, name, address, city);

    items.push({
      hotelId,
      name,
      lat: Number.isFinite(lat) ? lat : null,
      lng: Number.isFinite(lng) ? lng : null,
      address,
      rating,
      price,
      offer: offerPayload,
      bookingUrl: null,
    });
  }

  const itemsLimited = items.slice(0, outputMax);
  const itemsWithPhotos = await enrichHotelItemsWithPhotos(itemsLimited, city, req);
  console.log(
    "[Hotels DEBUG]",
    "requestId=" + requestId,
    "hotelIdsFound=" + hotelIds.length,
    "hotelIdsPriced=" + offersByHotelId.size,
    "offersCount=" + offersReturnedCount,
    "finalItems=" + itemsWithPhotos.length
  );
  logOfferFieldDebug(itemsWithPhotos, requestId);

  return res.json({
    ok: true,
    cached: false,
    query: { city: city || null, lat: searchLat, lng: searchLng, checkIn, nights, adults, radiusKm, max },
    items: itemsWithPhotos,
  });
});

// ---------------------------------------------
// Hotels Photo (lazy)
// GET /v1/hotels/photo?hotelId=...&maxWidth=...
// ---------------------------------------------
app.get("/v1/hotels/photo", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;

  const hotelIdRaw = String(req.query.hotelId || "").trim();
  if (!hotelIdRaw) {
    return res.status(400).json({ ok: false, error: "Missing hotelId" });
  }
  if (hotelIdRaw.length > 200) {
    return res.status(400).json({ ok: false, error: "Invalid hotelId" });
  }

  const hotelIdKey = normalizeCacheKeyPart(hotelIdRaw);
  if (!hotelIdKey) {
    return res.status(400).json({ ok: false, error: "Invalid hotelId" });
  }

  let maxWidth = HOTEL_PHOTO_MAX_WIDTH;
  const maxWidthParam = req.query.maxWidth;
  if (maxWidthParam !== undefined) {
    if (typeof maxWidthParam !== "string") {
      return res.status(400).json({ ok: false, error: "Invalid maxWidth: must be a string number" });
    }
    const parsed = parseInt(maxWidthParam, 10);
    if (!Number.isFinite(parsed)) {
      return res.status(400).json({ ok: false, error: "Invalid maxWidth: must be numeric" });
    }
    maxWidth = Math.min(1600, Math.max(100, parsed));
  }

  const debugEnabled = isHotelsDebugEnabled();
  const debugLogEnabled = isHotelsDebugLoggingEnabled();

  const cached = hotelPhotoRefCache.get(hotelIdKey);
  if (cached) {
    const photoUrl = cached.photoRef ? buildPlacesPhotoUrl(req, cached.photoRef, maxWidth) : null;
    const debug = debugEnabled
      ? {
          triedQueries: Array.isArray(cached?.debug?.triedQueries) ? cached.debug.triedQueries : [],
          chosenQuery: cached?.debug?.chosenQuery || null,
          googleSearchResultsCount: typeof cached?.debug?.googleSearchResultsCount === "number" ? cached.debug.googleSearchResultsCount : 0,
          chosenPlaceId: cached?.placeId || null,
          detailsPhotosCount: typeof cached?.debug?.detailsPhotosCount === "number" ? cached.debug.detailsPhotosCount : null,
          reason: photoUrl ? "ok" : cached?.debug?.reason || "no_photos_in_details",
        }
      : undefined;
    if (debugLogEnabled) {
      console.log("[Hotels PHOTO]", JSON.stringify(debug));
    }
    return res.json({ ok: true, hotelId: hotelIdRaw, cached: true, photoUrl, ...(debugEnabled ? { debug } : {}) });
  }

  if (!GOOGLE_PLACES_API_KEY) {
    const debug = debugEnabled
      ? {
          triedQueries: [],
          chosenQuery: null,
          googleSearchResultsCount: 0,
          chosenPlaceId: null,
          detailsPhotosCount: null,
          reason: "no_google_results",
        }
      : undefined;
    if (debugLogEnabled) {
      console.log("[Hotels PHOTO]", JSON.stringify(debug));
    }
    return res.json({ ok: true, hotelId: hotelIdRaw, cached: false, photoUrl: null, ...(debugEnabled ? { debug } : {}) });
  }

  const details = hotelDetailsCache.get(hotelIdKey);
  if (!details) {
    const debug = debugEnabled
      ? {
          triedQueries: [],
          chosenQuery: null,
          googleSearchResultsCount: 0,
          chosenPlaceId: null,
          detailsPhotosCount: null,
          reason: "no_hotel_context",
        }
      : undefined;
    if (debugLogEnabled) {
      console.log("[Hotels PHOTO]", JSON.stringify(debug));
    }
    return res.json({ ok: true, hotelId: hotelIdRaw, cached: false, photoUrl: null, ...(debugEnabled ? { debug } : {}) });
  }

  let result;
  try {
    result = await fetchHotelPhotoReferenceByDetails(hotelIdRaw, details);
  } catch (_) {
    result = { photoRef: null, placeId: null, placeName: null, photosCount: 0, candidatesCount: 0, query: null, triedQueries: [], reason: "unexpected" };
  }
  const photoRef = result?.photoRef || null;
  const ttl = photoRef ? HOTEL_PHOTO_REF_TTL_MS : HOTEL_PHOTO_REF_NULL_TTL_MS;
  hotelPhotoRefCache.set(
    hotelIdKey,
    {
      photoRef,
      placeId: result?.placeId || null,
      placeName: result?.placeName || null,
      debug: {
        triedQueries: Array.isArray(result?.triedQueries) ? result.triedQueries : [],
        chosenQuery: result?.query || null,
        googleSearchResultsCount: typeof result?.candidatesCount === "number" ? result.candidatesCount : 0,
        detailsPhotosCount: typeof result?.photosCount === "number" ? result.photosCount : null,
        reason: result?.reason || (photoRef ? "ok" : "no_photos_in_details"),
      },
    },
    ttl
  );
  const photoUrl = photoRef ? buildPlacesPhotoUrl(req, photoRef, maxWidth) : null;
  const debug = debugEnabled
    ? {
        triedQueries: Array.isArray(result?.triedQueries) ? result.triedQueries : [],
        chosenQuery: result?.query || null,
        googleSearchResultsCount: typeof result?.candidatesCount === "number" ? result.candidatesCount : 0,
        chosenPlaceId: result?.placeId || null,
        detailsPhotosCount: typeof result?.photosCount === "number" ? result.photosCount : null,
        reason: result?.reason || (photoUrl ? "ok" : "no_photos_in_details"),
      }
    : undefined;
  if (debugLogEnabled) {
    console.log("[Hotels PHOTO]", JSON.stringify({ ...debug, returned: photoUrl ? "photoUrl" : "null" }));
  }
  return res.json({ ok: true, hotelId: hotelIdRaw, cached: false, photoUrl, ...(debugEnabled ? { debug } : {}) });
});

// ---------------------------------------------
// Places Details (proxy)
// GET /v1/places/details?placeId=...
// ---------------------------------------------
app.get("/v1/places/details", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;

  if (!GOOGLE_PLACES_API_KEY) {
    return res.status(500).json({ ok: false, error: "GOOGLE_PLACES_API_KEY not set" });
  }

  const placeId = String(req.query.placeId || "").trim();
  if (!placeId) {
    return res.status(400).json({ ok: false, error: "Missing placeId" });
  }
  if (placeId.length > 200) {
    return res.status(400).json({ ok: false, error: "Invalid placeId" });
  }

  // rate limit
  const limiterId = getRateLimitKey(req, userId);
  const lim = placesDetailsLimiter.allow(`details:${limiterId}`);
  if (!lim.ok) {
    return res.status(429).json({ ok: false, error: "Rate limit exceeded" });
  }

  // cache (24h)
  const cached = placesDetailsCache.get(placeId);
  if (cached) {
    console.log("[Places DETAILS]", "userId=" + userId, "placeId=" + placeId, "cacheHit=true");
    return res.json({ ok: true, cached: true, item: cached });
  }

  try {
    // lean fields only (keeps payload small)
    const fields = [
      "place_id",
      "name",
      "formatted_address",
      "geometry/location",
      "rating",
      "user_ratings_total",
      "website",
      "formatted_phone_number",
      "opening_hours/open_now",
      "opening_hours/weekday_text",
      "price_level",
      "photos",
      "business_status",
    ].join(",");

    const url =
      "https://maps.googleapis.com/maps/api/place/details/json" +
      "?place_id=" + encodeURIComponent(placeId) +
      "&fields=" + encodeURIComponent(fields) +
      "&key=" + encodeURIComponent(GOOGLE_PLACES_API_KEY);

    const r = await fetchWithTimeout(url);
    const json = await r.json();

    if (!r.ok || json.status !== "OK") {
      const msg = json?.error_message || ("Google details failed: " + String(json.status || r.status));
      console.log("[Places DETAILS]", "userId=" + userId, "placeId=" + placeId, "cacheHit=false", "status=" + String(json.status || r.status));
      return res.status(502).json({ ok: false, error: "Google details fetch failed", detail: msg });
    }

    const p = json.result || {};
    const loc = p.geometry?.location || null;

    const primaryPhotoReference =
      Array.isArray(p.photos) && p.photos.length > 0 ? String(p.photos[0].photo_reference || "") : "";

    const item = {
      placeId: String(p.place_id || placeId),
      name: String(p.name || ""),
      formattedAddress: p.formatted_address ? String(p.formatted_address) : null,
      location: loc && typeof loc.lat === "number" && typeof loc.lng === "number" ? { lat: loc.lat, lng: loc.lng } : null,
      rating: typeof p.rating === "number" ? p.rating : null,
      userRatingsTotal: typeof p.user_ratings_total === "number" ? p.user_ratings_total : null,
      website: p.website ? String(p.website) : null,
      phone: p.formatted_phone_number ? String(p.formatted_phone_number) : null,
      openNow: typeof p.opening_hours?.open_now === "boolean" ? p.opening_hours.open_now : null,
      weekdayText: Array.isArray(p.opening_hours?.weekday_text) ? p.opening_hours.weekday_text : null,
      priceLevel: typeof p.price_level === "number" ? p.price_level : null,
      businessStatus: p.business_status ? String(p.business_status) : null,
      primaryPhotoReference: primaryPhotoReference || null,
    };

    placesDetailsCache.set(placeId, item, 24 * 60 * 60 * 1000);

    console.log("[Places DETAILS]", "userId=" + userId, "placeId=" + placeId, "cacheHit=false", "status=OK");
    return res.json({ ok: true, cached: false, item });
  } catch (e) {
    console.log("[Places DETAILS] error:", e?.message || e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ---------------------------------------------
// Places Details Photos (proxy)
// GET /v1/places/details/photos?placeId=...&max=...
// ---------------------------------------------
app.get("/v1/places/details/photos", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;

  if (!GOOGLE_PLACES_API_KEY) {
    return res.status(500).json({ ok: false, error: "GOOGLE_PLACES_API_KEY not set" });
  }

  const placeId = String(req.query.placeId || "").trim();
  if (!placeId) {
    return res.status(400).json({ ok: false, error: "Missing placeId" });
  }
  if (placeId.length > 200) {
    return res.status(400).json({ ok: false, error: "Invalid placeId" });
  }

  const maxRaw = String(req.query.max || "").trim();
  const maxNum = maxRaw ? Number(maxRaw) : 12;
  let max = Number.isFinite(maxNum) ? Math.round(maxNum) : 12;
  if (max <= 0) max = 12;
  if (max > 20) max = 20;

  // rate limit
  const limiterId = getRateLimitKey(req, userId);
  const lim = placesDetailsPhotosLimiter.allow(`detailsPhotos:${limiterId}`);
  if (!lim.ok) {
    return res.status(429).json({ ok: false, error: "Rate limit exceeded" });
  }

  const plan = getPlanForNow(req);
  const daily = enforcePlacesDetailsPhotosDailyLimit(limiterId, plan);
  if (!daily.ok) {
    return res.status(daily.status).json({ ok: false, error: daily.error });
  }

  const cacheKey = `${placeId}:${max}`;
  const cached = placesDetailsPhotosCache.get(cacheKey);
  if (cached) {
    const count = Array.isArray(cached) ? cached.length : 0;
    console.log("[Places DETAILS PHOTOS]", "userId=" + userId, "placeId=" + placeId, "cacheHit=true", "count=" + count);
    return res.json({ ok: true, cached: true, placeId, photoReferences: cached });
  }

  try {
    const url =
      "https://maps.googleapis.com/maps/api/place/details/json" +
      "?place_id=" + encodeURIComponent(placeId) +
      "&fields=" + encodeURIComponent("photos") +
      "&key=" + encodeURIComponent(GOOGLE_PLACES_API_KEY);

    const r = await fetchWithTimeout(url);
    const json = await r.json();

    if (!r.ok || json.status !== "OK") {
      const msg = json?.error_message || ("Google details failed: " + String(json.status || r.status));
      console.log(
        "[Places DETAILS PHOTOS]",
        "userId=" + userId,
        "placeId=" + placeId,
        "cacheHit=false",
        "status=" + String(json.status || r.status)
      );
      return res.status(502).json({ ok: false, error: "Google details photos fetch failed", detail: msg });
    }

    const photos = Array.isArray(json.result?.photos) ? json.result.photos : [];
    const photoReferences = photos
      .map((p) => String(p?.photo_reference || "").trim())
      .filter((ref) => ref)
      .slice(0, max);

    placesDetailsPhotosCache.set(cacheKey, photoReferences, 24 * 60 * 60 * 1000);

    console.log(
      "[Places DETAILS PHOTOS]",
      "userId=" + userId,
      "placeId=" + placeId,
      "cacheHit=false",
      "count=" + photoReferences.length
    );
    return res.json({ ok: true, cached: false, placeId, photoReferences });
  } catch (e) {
    console.log("[Places DETAILS PHOTOS] error:", e?.message || e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ---------------------------------------------
// Places Photo (proxy)
// GET /v1/places/photo?ref=...&maxWidth=...
// ---------------------------------------------
app.get("/v1/places/photo", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;

  const apiKey = GOOGLE_PLACES_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ ok: false, error: "GOOGLE_PLACES_API_KEY not set" });
  }

  const refParam = req.query.ref;
  if (refParam === undefined) {
    return res.status(400).json({ ok: false, error: "Missing ref" });
  }
  if (typeof refParam !== "string") {
    return res.status(400).json({ ok: false, error: "Invalid ref: must be a string" });
  }
  const ref = refParam.trim();
  if (!ref) {
    return res.status(400).json({ ok: false, error: "Missing ref" });
  }
  if (ref.length < 20) {
    return res.status(400).json({ ok: false, error: "Invalid ref: too short (min 20 chars)" });
  }

  const maxWidthParam = req.query.maxWidth;
  let maxWidth = 800;
  if (maxWidthParam !== undefined) {
    if (typeof maxWidthParam !== "string") {
      return res.status(400).json({ ok: false, error: "Invalid maxWidth: must be a string number" });
    }
    const parsed = parseInt(maxWidthParam, 10);
    if (!Number.isFinite(parsed)) {
      return res.status(400).json({ ok: false, error: "Invalid maxWidth: must be numeric" });
    }
    maxWidth = Math.min(1600, Math.max(100, parsed));
  }
  const cacheKey = `${ref}:${maxWidth}`;

  const cached = getCachedPhoto(cacheKey);
  if (cached) {
    res.setHeader("Content-Type", cached.contentType || "image/jpeg");
    res.setHeader("Cache-Control", "public, max-age=86400"); // 1 day client cache hint
    return res.send(cached.buf);
  }

  const plan = getPlanForNow(req);
  const limiterId = getRateLimitKey(req, userId);
  const lim = enforcePhotoLimits(limiterId, plan);
  if (!lim.ok) {
    return res.status(lim.status).json({ ok: false, error: lim.error });
  }

  // call Google Places Photo
  const url =
    `https://maps.googleapis.com/maps/api/place/photo` +
    `?maxwidth=${encodeURIComponent(String(maxWidth))}` +
    `&photoreference=${encodeURIComponent(ref)}` +
    `&key=${encodeURIComponent(apiKey)}`;

  try {
    const r = await fetchWithTimeout(url, { redirect: "follow" }, 12000);

    if (!r.ok) {
      const text = await r.text().catch(() => "");
      return res.status(502).json({
        ok: false,
        error: "Google photo fetch failed",
        upstreamStatus: r.status,
        detail: text ? text.slice(0, 200) : "",
      });
    }

    const contentType = r.headers.get("content-type") || "image/jpeg";
    const buf = Buffer.from(await r.arrayBuffer());

    // store in cache (7 days)
    photoCache.set(cacheKey, {
      buf,
      contentType,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
    });

    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "public, max-age=86400"); // 1 day client cache hint
    return res.send(buf);
  } catch (e) {
    console.log("[PlacesPhoto] error:", e?.message || e);
    return res.status(500).json({ ok: false, error: "Server error fetching photo" });
  }
});


app.post("/v1/places/eta", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;

  if (!GOOGLE_PLACES_API_KEY) {
    return res.status(500).json({ ok: false, error: "GOOGLE_PLACES_API_KEY not set" });
  }

  const origin = req.body?.origin || {};
  const dest = req.body?.dest || {};
  const originLat = Number(origin.lat);
  const originLng = Number(origin.lng);
  const destLat = Number(dest.lat);
  const destLng = Number(dest.lng);

  if (
    !Number.isFinite(originLat) ||
    !Number.isFinite(originLng) ||
    !Number.isFinite(destLat) ||
    !Number.isFinite(destLng)
  ) {
    return res.status(400).json({ ok: false, error: "Missing or invalid origin/dest" });
  }
  if (
    originLat < -90 ||
    originLat > 90 ||
    originLng < -180 ||
    originLng > 180 ||
    destLat < -90 ||
    destLat > 90 ||
    destLng < -180 ||
    destLng > 180
  ) {
    return res.status(400).json({ ok: false, error: "Invalid origin/dest bounds" });
  }

  const mode = String(req.body?.mode || "driving").toLowerCase();
  if (mode !== "driving" && mode !== "walking") {
    return res.status(400).json({ ok: false, error: "Invalid mode" });
  }

  const trafficRaw = req.body?.traffic;
  let traffic = false;
  if (mode === "driving") {
    if (trafficRaw === undefined) {
      traffic = true;
    } else if (typeof trafficRaw !== "boolean") {
      return res.status(400).json({ ok: false, error: "Invalid traffic" });
    } else {
      traffic = trafficRaw;
    }
  } else if (trafficRaw === true) {
    return res.status(400).json({ ok: false, error: "Traffic only allowed for driving" });
  }

  const plan = getPlanForNow(req);
  const limiterId = getRateLimitKey(req, userId);
  const lim = enforceEtaLimits(limiterId, plan);
  if (!lim.ok) {
    return res.status(429).json({ ok: false, error: lim.error });
  }

  console.log(
    "[ETA LIMIT]",
    "userId=" + userId,
    "minute=" + lim.minuteCount + "/" + lim.rpmLimit,
    "hour=" + lim.hourCount + "/" + lim.hourlyLimit,
    "day=" + lim.dayCount + "/" + lim.dailyLimit
  );

  const coordKey = (n) => (Math.round(n * 10000) / 10000).toFixed(4);
  const cacheKey = [
    "eta",
    coordKey(originLat),
    coordKey(originLng),
    coordKey(destLat),
    coordKey(destLng),
    mode,
    traffic ? "1" : "0",
  ].join(":");

  const cached = etaCache.get(cacheKey);
  if (cached) {
    const minutes = cached.minutes;
    const meters = cached.meters;
    const cachedFlag = true;
    console.log(
      "[ETA]",
      "userId=" + userId,
      "mode=" + mode,
      "traffic=" + traffic,
      "cached=" + cachedFlag,
      "minutes=" + minutes,
      "meters=" + meters
    );
    return res.json({ ok: true, cached: true, minutes, meters, mode, traffic });
  }

  let url =
    "https://maps.googleapis.com/maps/api/distancematrix/json" +
    "?origins=" + encodeURIComponent(`${originLat},${originLng}`) +
    "&destinations=" + encodeURIComponent(`${destLat},${destLng}`) +
    "&mode=" + encodeURIComponent(mode) +
    "&key=" + encodeURIComponent(GOOGLE_PLACES_API_KEY);

  if (mode === "driving" && traffic) {
    url += "&departure_time=now";
  }

  try {
    const r = await fetchWithTimeout(url);
    const json = await r.json();

    if (!r.ok || json.status !== "OK") {
      const detail = json?.error_message || String(json.status || r.status);
      return res.status(502).json({ ok: false, error: "Google ETA failed", detail });
    }

    const element = json?.rows?.[0]?.elements?.[0];
    if (!element || element.status !== "OK") {
      const detail = String(element?.status || "NO_ELEMENTS");
      return res.status(502).json({ ok: false, error: "Google ETA failed", detail });
    }

    const duration = mode === "driving" && traffic ? element.duration_in_traffic : element.duration;
    const durationValue = Number(duration?.value);
    const distanceValue = Number(element.distance?.value);

    if (!Number.isFinite(durationValue) || !Number.isFinite(distanceValue)) {
      return res.status(502).json({ ok: false, error: "Google ETA failed", detail: "Missing duration/distance" });
    }

    const minutes = Math.round(durationValue / 60);
    const meters = Math.round(distanceValue);
    let ttlMs = 60 * 1000;
    if (mode === "walking" || (mode === "driving" && !traffic)) {
      ttlMs = 10 * 60 * 1000;
    }

    etaCache.set(cacheKey, { minutes, meters }, ttlMs);

    const cachedFlag = false;
    console.log(
      "[ETA]",
      "userId=" + userId,
      "mode=" + mode,
      "traffic=" + traffic,
      "cached=" + cachedFlag,
      "minutes=" + minutes,
      "meters=" + meters
    );

    return res.json({ ok: true, cached: false, minutes, meters, mode, traffic });
  } catch (e) {
    console.log("[ETA] error:", e?.message || e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ---------------------------------------------
// One-time DB init
// ---------------------------------------------
app.post("/admin/init", async (req, res) => {
  if (!dbPool) {
    return res.status(500).json({ ok: false, error: "DATABASE_URL not set" });
  }

  try {
    await dbPool.query(`
      create table if not exists saved_items (
        id uuid primary key default gen_random_uuid(),
        user_id text not null,
        kind text not null,
        external_id text not null,
        payload jsonb not null default '{}'::jsonb,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now(),
        deleted_at timestamptz
      );

      create index if not exists idx_saved_items_user_kind
        on saved_items(user_id, kind);

      create index if not exists idx_saved_items_user_updated
        on saved_items(user_id, updated_at);

      drop index if exists uq_saved_items_user_kind_ext;

      create unique index if not exists uq_saved_items_user_kind_ext
        on saved_items(user_id, kind, external_id);
    `);

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});
// ---------------------------------------------
// Simple in-memory rate limits + cache (starter)
// NOTE: resets when server restarts, good for MVP
// ---------------------------------------------
const etaHourlyCounters = new Map(); // key: userId:YYYY-MM-DDTHH -> count
const etaDailyCounters = new Map(); // key: userId:YYYY-MM-DD -> count
const photoMinuteCounters = new Map(); // key: userId:minute -> count
const photoDailyCounters = new Map();  // key: userId:YYYY-MM-DD -> count
const photoCache = new Map();          // key: ref:maxWidth -> { buf, contentType, expiresAt }

function nowMinuteKey() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}T${String(d.getUTCHours()).padStart(2,"0")}:${String(d.getUTCMinutes()).padStart(2,"0")}`;
}

function todayKey() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}`;
}

function hourKeyUTC() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}T${String(d.getUTCHours()).padStart(2,"0")}`;
}

function getEnvInt(name, fallback) {
  const raw = process.env[name];
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function getPlanForNow(req) {
  // TODO: wire real free/paid from DB or subscription
  // For now: treat all authenticated users as "paid"
  return "paid";
}

function enforceHotelsHourlyDaily(limiterId) {
  const hour = hourKeyUTC();
  const day = todayKey();

  const hourlyLimit = getEnvInt("HOTELS_HOURLY", 50);
  const dailyLimit = getEnvInt("HOTELS_DAILY", 100);

  const hourKey = `${limiterId}:${hour}`;
  const dayKey = `${limiterId}:${day}`;

  const hourCount = (hotelsHourlyCounters.get(hourKey) || 0) + 1;
  const dayCount = (hotelsDailyCounters.get(dayKey) || 0) + 1;

  if (hourlyLimit >= 0 && hourCount > hourlyLimit) {
    return { ok: false, status: 429, error: "Hotel hourly limit reached. Try again later." };
  }
  if (dailyLimit >= 0 && dayCount > dailyLimit) {
    return { ok: false, status: 429, error: "Hotel daily limit reached. Try again tomorrow." };
  }

  hotelsHourlyCounters.set(hourKey, hourCount);
  hotelsDailyCounters.set(dayKey, dayCount);

  return { ok: true, hourCount, dayCount, hourlyLimit, dailyLimit };
}

function enforcePhotoLimits(limiterId, plan) {
  const minute = nowMinuteKey();
  const day = todayKey();

  const rpmFree = getEnvInt("PLACES_PHOTO_RPM_FREE", 1);
  const rpmPaid = getEnvInt("PLACES_PHOTO_RPM_PAID", 60);
  const dailyFree = getEnvInt("PLACES_PHOTO_DAILY_FREE", 1);
  const dailyPaid = getEnvInt("PLACES_PHOTO_DAILY_PAID", 120);

  const rpmLimit = plan === "paid" ? rpmPaid : rpmFree;
  const dailyLimit = plan === "paid" ? dailyPaid : dailyFree;

  const minuteKey = `${limiterId}:${minute}`;
  const dayKey = `${limiterId}:${day}`;

  const minuteCount = (photoMinuteCounters.get(minuteKey) || 0) + 1;
  const dayCount = (photoDailyCounters.get(dayKey) || 0) + 1;

  if (rpmLimit >= 0 && minuteCount > rpmLimit) {
    return { ok: false, status: 429, error: `Rate limit exceeded (photos per minute). Try again shortly.` };
  }
  if (dailyLimit >= 0 && dayCount > dailyLimit) {
    return { ok: false, status: 429, error: `Daily photo limit reached. Try again tomorrow.` };
  }

  photoMinuteCounters.set(minuteKey, minuteCount);
  photoDailyCounters.set(dayKey, dayCount);

  return { ok: true, minuteCount, dayCount, rpmLimit, dailyLimit };
}

function enforceEtaLimits(limiterId, plan) {
  const hour = hourKeyUTC();
  const day = todayKey();

  const rpmFree = getEnvInt("ETA_RPM_FREE", 1);
  const rpmPaid = getEnvInt("ETA_RPM_PAID", 10);
  const hourlyFree = getEnvInt("ETA_HOURLY_FREE", 1);
  const hourlyPaid = getEnvInt("ETA_HOURLY_PAID", 20);
  const dailyFree = getEnvInt("ETA_DAILY_FREE", 1);
  const dailyPaid = getEnvInt("ETA_DAILY_PAID", 30);

  const isPaid = plan === "paid";
  const rpmLimit = isPaid ? rpmPaid : rpmFree;
  const hourlyLimit = isPaid ? hourlyPaid : hourlyFree;
  const dailyLimit = isPaid ? dailyPaid : dailyFree;

  const hourKey = `${limiterId}:${hour}`;
  const dayKey = `${limiterId}:${day}`;

  let minuteCount = 0;
  if (rpmLimit >= 0) {
    const minuteLimiter = isPaid ? etaMinuteLimiterPaid : etaMinuteLimiterFree;
    const minuteResult = minuteLimiter.allow(`eta:${limiterId}`);
    if (!minuteResult.ok) {
      return { ok: false, status: 429, error: "ETA rate limit exceeded (per minute). Try again shortly." };
    }
    minuteCount = rpmLimit - minuteResult.remaining;
  }
  const hourCount = (etaHourlyCounters.get(hourKey) || 0) + 1;
  const dayCount = (etaDailyCounters.get(dayKey) || 0) + 1;

  if (hourlyLimit >= 0 && hourCount > hourlyLimit) {
    return { ok: false, status: 429, error: "ETA hourly limit reached. Try again later." };
  }
  if (dailyLimit >= 0 && dayCount > dailyLimit) {
    return { ok: false, status: 429, error: "ETA daily limit reached. Try again tomorrow." };
  }

  etaHourlyCounters.set(hourKey, hourCount);
  etaDailyCounters.set(dayKey, dayCount);

  return { ok: true, minuteCount, hourCount, dayCount, rpmLimit, hourlyLimit, dailyLimit };
}

function enforcePlacesDetailsPhotosDailyLimit(limiterId, plan) {
  const day = todayKey();

  const dailyFree = getEnvInt("PLACES_DETAILS_PHOTOS_DAILY_FREE", 10);
  const dailyPaid = getEnvInt("PLACES_DETAILS_PHOTOS_DAILY_PAID", 60);

  const dailyLimit = plan === "paid" ? dailyPaid : dailyFree;
  const dayKey = `${limiterId}:${day}`;
  const dayCount = (placesDetailsPhotosDailyCounters.get(dayKey) || 0) + 1;

  if (dailyLimit >= 0 && dayCount > dailyLimit) {
    return { ok: false, status: 429, error: "Daily details photos limit reached. Try again tomorrow." };
  }

  placesDetailsPhotosDailyCounters.set(dayKey, dayCount);
  return { ok: true, dayCount, dailyLimit };
}

function getCachedPhoto(cacheKey) {
  const hit = photoCache.get(cacheKey);
  if (!hit) return null;
  if (Date.now() > hit.expiresAt) {
    photoCache.delete(cacheKey);
    return null;
  }
  return hit;
}

function validateSavedPayload(payload) {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return { ok: false, error: "Invalid payload" };
  }

  const maxBytes = 32 * 1024;
  const maxStringLen = 2000;
  try {
    const json = JSON.stringify(payload);
    if (Buffer.byteLength(json, "utf8") > maxBytes) {
      return { ok: false, error: "Payload too large" };
    }
  } catch (_) {
    return { ok: false, error: "Invalid payload" };
  }

  const seen = new Set();
  function walk(val, depth) {
    if (typeof val === "string") return val.length <= maxStringLen;
    if (typeof val !== "object" || val === null) return true;
    if (seen.has(val)) return true;
    if (depth <= 0) return false;
    seen.add(val);
    if (Array.isArray(val)) {
      for (const item of val) {
        if (!walk(item, depth - 1)) return false;
      }
    } else {
      for (const v of Object.values(val)) {
        if (!walk(v, depth - 1)) return false;
      }
    }
    return true;
  }

  if (!walk(payload, 5)) {
    return { ok: false, error: "Payload too large" };
  }

  return { ok: true };
}

// ---------------------------------------------
// Helpers
// ---------------------------------------------
function addNightsToDate(checkIn, nights) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(checkIn)) return null;
  const date = new Date(`${checkIn}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return null;
  const out = new Date(date.getTime());
  out.setUTCDate(out.getUTCDate() + nights);
  return out.toISOString().slice(0, 10);
}

function truncateText(value, maxLen) {
  const text = String(value || "");
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen);
}

function setOptionalQueryParam(url, key, value) {
  if (!url || !key) return;
  if (value === undefined || value === null) return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return;
    url.searchParams.set(key, String(value));
    return;
  }
  const text = String(value).trim();
  if (!text) return;
  url.searchParams.set(key, text);
}

function shouldLogHotelsUrl() {
  const debug = String(process.env.DEBUG_HOTELS || "").trim().toLowerCase();
  if (debug === "true") return true;
  const env = String(process.env.NODE_ENV || "").trim().toLowerCase();
  return env !== "production";
}

function chunkArray(items, size) {
  const out = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(items.slice(i, i + size));
  }
  return out;
}

function safeJsonParse(text) {
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch (_) {
    return {};
  }
}

function getUrlHost(rawUrl) {
  try {
    return new URL(rawUrl).host;
  } catch (_) {
    return "";
  }
}

function normalizeCacheKeyPart(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

function makeHotelPhotoCacheKey(hotelId, name, city) {
  const id = normalizeCacheKeyPart(hotelId);
  if (id) return `hotelId:${id}`;
  const nameKey = normalizeCacheKeyPart(name);
  if (!nameKey) return "";
  const cityKey = normalizeCacheKeyPart(city);
  return `hotelName:${nameKey}|${cityKey}`;
}

function buildHotelTextSearchQuery(name, address, city) {
  const parts = [];
  if (name) parts.push(name);
  if (address) {
    parts.push(address);
  } else if (city) {
    parts.push(city);
  }
  return truncateText(parts.join(" ").trim(), 200);
}

function getApiBase(req) {
  const envBase = String(process.env.API_BASE || "").trim();
  let base = envBase;
  if (!base) {
    const host = req.get("host");
    const protocol = req.protocol || "http";
    base = host ? `${protocol}://${host}` : "";
  }
  if (!base) return "";
  return base.endsWith("/") ? base.slice(0, -1) : base;
}

function buildPlacesPhotoUrl(req, photoRef, maxWidth = HOTEL_PHOTO_MAX_WIDTH) {
  if (!photoRef) return null;
  const base = getApiBase(req);
  if (!base) return null;
  return `${base}/v1/places/photo?ref=${encodeURIComponent(photoRef)}&maxWidth=${encodeURIComponent(String(maxWidth))}`;
}

function isHotelsDebugEnabled() {
  const debug = String(process.env.DEBUG_HOTELS || "").trim().toLowerCase();
  if (debug === "true") return true;
  const env = String(process.env.NODE_ENV || "").trim().toLowerCase();
  return env !== "production";
}

function isHotelsDebugLoggingEnabled() {
  const debug = String(process.env.DEBUG_HOTELS || "").trim().toLowerCase();
  return debug === "true";
}

function splitAddressParts(address) {
  if (!address) return [];
  return String(address)
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function deriveCountryFromAddress(address) {
  const parts = splitAddressParts(address);
  if (parts.length === 0) return null;
  return parts[parts.length - 1] || null;
}

function deriveCityFromAddress(address) {
  const parts = splitAddressParts(address);
  if (parts.length < 2) return null;
  return parts[parts.length - 2] || null;
}

function cacheHotelDetails(hotelId, name, address, city) {
  const id = normalizeCacheKeyPart(hotelId);
  const hotelName = String(name || "").trim();
  if (!id || !hotelName) return;
  const derivedCity = city ? String(city) : deriveCityFromAddress(address);
  const derivedCountry = deriveCountryFromAddress(address);
  const record = {
    name: hotelName,
    address: address ? String(address) : null,
    city: derivedCity || null,
    country: derivedCountry || null,
  };
  hotelDetailsCache.set(id, record, HOTEL_DETAILS_TTL_MS);
}

async function fetchHotelPhotoReferenceByDetails(hotelId, details) {
  if (!details) return null;
  if (!GOOGLE_PLACES_API_KEY) return null;
  return await fetchHotelPhotoReferenceWithFallback(details);
}

function buildHotelPhotoQueries(details) {
  const name = String(details?.name || "").trim();
  if (!name) return [];
  const address = String(details?.address || "").trim();
  const city = String(details?.city || "").trim() || deriveCityFromAddress(details?.address);
  const queries = [];
  if (address && city) {
    queries.push(`${name} ${address} ${city} Canada`);
  }
  if (city) {
    queries.push(`${name} ${city} Canada`);
    queries.push(`${name} ${city}`);
  }
  queries.push(`${name}`);
  const seen = new Set();
  const out = [];
  for (const q of queries) {
    const trimmed = truncateText(String(q || "").trim(), 200);
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

async function fetchHotelPhotoReferenceWithFallback(details) {
  const queries = buildHotelPhotoQueries(details);
  if (queries.length === 0) {
    return {
      photoRef: null,
      placeId: null,
      placeName: null,
      photosCount: 0,
      candidatesCount: 0,
      query: null,
      triedQueries: [],
      reason: "no_hotel_context",
    };
  }
  let lastResult = null;
  for (const query of queries) {
    const result = await fetchPlacesFindPlacePhotoReference(query);
    lastResult = { ...result, query };
    if (result.photoRef) {
      return {
        photoRef: result.photoRef,
        placeId: result.placeId,
        placeName: result.placeName,
        photosCount: result.photosCount,
        candidatesCount: result.candidatesCount,
        query,
        triedQueries: queries,
        reason: null,
      };
    }
  }
  if (lastResult) {
    return { ...lastResult, triedQueries: queries };
  }
  return lastResult;
}

async function fetchPlacesDetailsPhotoReference(placeId) {
  if (!GOOGLE_PLACES_API_KEY) {
    return { photoRef: null, photosCount: 0 };
  }
  const url =
    "https://maps.googleapis.com/maps/api/place/details/json" +
    "?place_id=" + encodeURIComponent(placeId) +
    "&fields=" + encodeURIComponent("photos") +
    "&key=" + encodeURIComponent(GOOGLE_PLACES_API_KEY);

  try {
    const r = await fetchWithTimeout(url);
    const json = await r.json().catch(() => ({}));
    if (!r.ok || json.status !== "OK") {
      return { photoRef: null, photosCount: 0 };
    }
    const photos = Array.isArray(json.result?.photos) ? json.result.photos : [];
    const photoRef = String(photos[0]?.photo_reference || "").trim() || null;
    return { photoRef, photosCount: photos.length };
  } catch (_) {
    return { photoRef: null, photosCount: 0 };
  }
}

async function fetchPlacesFindPlacePhotoReference(query) {
  if (!GOOGLE_PLACES_API_KEY) {
    return { photoRef: null, placeId: null, placeName: null, photosCount: 0, candidatesCount: 0, reason: "no_google_results" };
  }
  const url =
    "https://maps.googleapis.com/maps/api/place/findplacefromtext/json" +
    "?input=" + encodeURIComponent(query) +
    "&inputtype=textquery" +
    "&fields=" + encodeURIComponent("place_id,name") +
    "&key=" + encodeURIComponent(GOOGLE_PLACES_API_KEY);

  let r;
  let json = {};
  try {
    r = await fetchWithTimeout(url);
    json = await r.json().catch(() => ({}));
  } catch (_) {
    return { photoRef: null, placeId: null, placeName: null, photosCount: 0, candidatesCount: 0, reason: "unexpected" };
  }
  const candidates = Array.isArray(json?.candidates) ? json.candidates : [];
  const candidatesCount = candidates.length;
  if (candidatesCount === 0) {
    return { photoRef: null, placeId: null, placeName: null, photosCount: 0, candidatesCount, reason: "no_google_results" };
  }
  for (const candidate of candidates) {
    const placeId = String(candidate?.place_id || "").trim();
    if (!placeId) continue;
    const placeName = String(candidate?.name || "").trim() || null;
    const details = await fetchPlacesDetailsPhotoReference(placeId);
    return {
      photoRef: details.photoRef,
      placeId,
      placeName,
      photosCount: details.photosCount,
      candidatesCount,
      reason: details.photoRef ? null : "no_photos_in_details",
    };
  }
  return {
    photoRef: null,
    placeId: null,
    placeName: null,
    photosCount: 0,
    candidatesCount,
    reason: "no_place_id",
  };
}

async function fetchHotelPrimaryPhotoReference(item, fallbackCity) {
  if (!GOOGLE_PLACES_API_KEY) return null;
  const hotelId = String(item?.hotelId || "").trim();
  const name = String(item?.name || "").trim();
  const address = String(item?.address || "").trim();
  const city = String(fallbackCity || "").trim();
  const cacheKey = makeHotelPhotoCacheKey(hotelId, name, city || address);
  if (cacheKey) {
    const cached = hotelPhotoCache.get(cacheKey);
    if (cached) return cached.photoRef || null;
  }
  if (!name) {
    if (cacheKey) hotelPhotoCache.set(cacheKey, { photoRef: null }, HOTEL_PHOTO_TTL_MS);
    return null;
  }
  const query = buildHotelTextSearchQuery(name, address, city);
  if (!query) {
    if (cacheKey) hotelPhotoCache.set(cacheKey, { photoRef: null }, HOTEL_PHOTO_TTL_MS);
    return null;
  }

  let photoRef = null;
  try {
    const url =
      "https://maps.googleapis.com/maps/api/place/textsearch/json" +
      "?query=" + encodeURIComponent(query) +
      "&type=lodging" +
      "&key=" + encodeURIComponent(GOOGLE_PLACES_API_KEY);

    const r = await fetchWithTimeout(url);
    const json = await r.json().catch(() => ({}));
    if (r.ok && json.status === "OK") {
      const first = Array.isArray(json.results) ? json.results[0] : null;
      const ref = first?.photos?.[0]?.photo_reference;
      photoRef = String(ref || "").trim() || null;
    }
  } catch (_) {
    photoRef = null;
  }

  if (cacheKey) hotelPhotoCache.set(cacheKey, { photoRef }, HOTEL_PHOTO_TTL_MS);
  return photoRef;
}

async function enrichHotelItemsWithPhotos(items, city, req) {
  if (!Array.isArray(items) || items.length === 0) return items;
  if (!GOOGLE_PLACES_API_KEY) {
    return items.map((item) => ({ ...item, photoUrl: null }));
  }
  const enriched = await Promise.all(
    items.map(async (item) => {
      const photoRef = await fetchHotelPrimaryPhotoReference(item, city);
      const photoUrl = buildPlacesPhotoUrl(req, photoRef, HOTEL_PHOTO_MAX_WIDTH);
      return { ...item, photoUrl: photoUrl || null };
    })
  );
  return enriched;
}

function getAmadeusTokenUrl() {
  return `${AMADEUS_BASE_URL}/v1/security/oauth2/token`;
}

function formatAmadeusAddress(address) {
  if (!address || typeof address !== "object") return null;
  const parts = [];
  if (Array.isArray(address.lines) && address.lines.length > 0) {
    const line = address.lines.map((item) => String(item || "").trim()).filter(Boolean).join(", ");
    if (line) parts.push(line);
  }
  if (address.addressLine) parts.push(String(address.addressLine));
  if (address.line1) parts.push(String(address.line1));
  if (address.line2) parts.push(String(address.line2));
  if (address.cityName) parts.push(String(address.cityName));
  if (address.stateCode) parts.push(String(address.stateCode));
  if (address.postalCode) parts.push(String(address.postalCode));
  if (address.countryCode) parts.push(String(address.countryCode));
  const formatted = parts.map((item) => String(item).trim()).filter(Boolean).join(", ");
  return formatted || null;
}

function parseAmadeusRating(value) {
  if (value === undefined || value === null) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function pickBestOfferPrice(offers) {
  if (!Array.isArray(offers)) return null;
  let best = null;
  for (const offer of offers) {
    const totalRaw = offer?.price?.total;
    const currencyRaw = offer?.price?.currency;
    const total = String(totalRaw || "").trim();
    const currency = String(currencyRaw || "").trim();
    const totalNum = Number(total);
    if (!Number.isFinite(totalNum) || !currency) continue;
    if (!best || totalNum < best.totalNum) {
      best = { total, currency, totalNum };
    }
  }
  if (!best) return null;
  return { total: best.total, currency: best.currency };
}

function pickBestOfferDetails(offers) {
  if (!Array.isArray(offers) || offers.length === 0) return null;
  let best = null;
  for (const offer of offers) {
    const price = buildOfferPrice(offer);
    if (!best) {
      best = { offer, price };
      continue;
    }
    const newTotal = price.totalNum;
    const oldTotal = best.price.totalNum;
    if (!Number.isFinite(oldTotal) && Number.isFinite(newTotal)) {
      best = { offer, price };
      continue;
    }
    if (Number.isFinite(newTotal) && Number.isFinite(oldTotal)) {
      const sameCurrency = !price.currency || !best.price.currency || price.currency === best.price.currency;
      if (sameCurrency && newTotal < oldTotal) {
        best = { offer, price };
      }
    }
  }
  if (!best) return null;
  return { offer: best.offer, price: best.price };
}

function buildOfferPrice(offer) {
  const price = offer?.price || {};
  const total = normalizeOfferValue(price.total);
  const base = normalizeOfferValue(price.base);
  const currency = normalizeOfferValue(price.currency);
  let taxes = null;
  if (price.taxes !== undefined && price.taxes !== null) {
    if (Array.isArray(price.taxes)) {
      let sum = 0;
      let count = 0;
      for (const item of price.taxes) {
        const amtRaw = item?.amount ?? item?.value;
        const amt = Number(amtRaw);
        if (Number.isFinite(amt)) {
          sum += amt;
          count += 1;
        }
      }
      if (count > 0) taxes = String(sum);
    } else {
      taxes = normalizeOfferValue(price.taxes);
    }
  }
  const totalNum = Number(total);
  return {
    total,
    base,
    taxes,
    currency,
    totalNum: Number.isFinite(totalNum) ? totalNum : null,
  };
}

function normalizeOfferValue(value) {
  const text = String(value ?? "").trim();
  return text ? text : null;
}

function pickOfferId(offer) {
  return normalizeOfferValue(offer?.id);
}

function pickOfferRoomType(offer) {
  const typeEstimated = offer?.room?.typeEstimated;
  return normalizeOfferValue(typeEstimated?.category || offer?.room?.type);
}

function pickOfferBedType(offer) {
  const typeEstimated = offer?.room?.typeEstimated;
  return normalizeOfferValue(typeEstimated?.bedType);
}

function pickOfferRoomDescription(offer) {
  return normalizeOfferValue(offer?.room?.description?.text);
}

function pickOfferBoardType(offer) {
  return normalizeOfferValue(offer?.boardType);
}

function pickOfferPaymentType(offer) {
  return normalizeOfferValue(offer?.paymentType);
}

function pickOfferCheckInDate(offer, fallback) {
  return normalizeOfferValue(offer?.checkInDate) || fallback;
}

function pickOfferCheckOutDate(offer, fallback, checkInDate, nights) {
  const raw = normalizeOfferValue(offer?.checkOutDate);
  if (raw) return raw;
  const derived = checkInDate && Number.isFinite(Number(nights))
    ? addNightsToDate(checkInDate, Number(nights))
    : null;
  return derived || fallback;
}

function pickOfferCancellation(offer) {
  let refundable = null;
  const refundableFlag = offer?.policies?.refundable?.cancellationRefundable;
  if (typeof refundableFlag === "boolean") {
    refundable = refundableFlag;
  } else if (typeof offer?.policies?.refundable === "boolean") {
    refundable = offer.policies.refundable;
  }

  const cancellations = Array.isArray(offer?.policies?.cancellations) ? offer.policies.cancellations : [];
  if (cancellations.length === 0) {
    return { refundable, cancellation: null };
  }

  let pick = null;
  let pickTime = null;
  for (const item of cancellations) {
    const deadlineRaw = item?.deadline;
    const deadlineTime = deadlineRaw ? new Date(deadlineRaw).getTime() : NaN;
    if (Number.isFinite(deadlineTime)) {
      if (pickTime === null || deadlineTime < pickTime) {
        pick = item;
        pickTime = deadlineTime;
      }
    } else if (!pick) {
      pick = item;
    }
  }

  if (!pick) {
    return { refundable, cancellation: null };
  }

  const deadline = normalizeOfferValue(pick?.deadline);
  const description = normalizeOfferValue(pick?.description?.text || pick?.description || pick?.policy?.text);
  return {
    refundable,
    cancellation: {
      deadline,
      description,
    },
  };
}

function buildOfferRawDebug(offer) {
  if (!offer) return null;
  const room = offer.room || null;
  const roomOut = room
    ? {
        type: normalizeOfferValue(room?.type),
        typeEstimated: room?.typeEstimated
          ? {
              category: normalizeOfferValue(room.typeEstimated?.category),
              bedType: normalizeOfferValue(room.typeEstimated?.bedType),
            }
          : null,
        description: normalizeOfferValue(room?.description?.text),
      }
    : null;
  const policies = offer.policies
    ? {
        refundable: offer.policies.refundable ?? null,
        cancellations: offer.policies.cancellations ?? null,
      }
    : null;
  return {
    rateCode: normalizeOfferValue(offer.rateCode),
    room: roomOut,
    policies,
    paymentType: normalizeOfferValue(offer.paymentType),
    boardType: normalizeOfferValue(offer.boardType),
  };
}

function logOfferFieldDebug(items, requestId) {
  const sample = Array.isArray(items) ? items.slice(0, 2) : [];
  for (let i = 0; i < sample.length; i += 1) {
    const item = sample[i] || {};
    const offer = item.offer || {};
    const cancellation = offer.cancellation || null;
    const cancelPresent = Boolean(cancellation && (cancellation.deadline || cancellation.description));
    console.log(
      "[Hotels DEBUG OFFER]",
      "requestId=" + requestId,
      "idx=" + i,
      "hotelId=" + String(item.hotelId || ""),
      "roomType=" + (offer.roomType ? "present" : "missing"),
      "boardType=" + (offer.boardType ? "present" : "missing"),
      "paymentType=" + (offer.paymentType ? "present" : "missing"),
      "cancellation=" + (cancelPresent ? "present" : "missing")
    );
  }
}

async function geocodeCityToLatLng(city) {
  const url =
    "https://maps.googleapis.com/maps/api/geocode/json" +
    "?address=" + encodeURIComponent(city) +
    "&key=" + encodeURIComponent(GOOGLE_PLACES_API_KEY);

  let r;
  try {
    r = await fetchWithTimeout(url);
  } catch (_) {
    return null;
  }
  const json = await r.json().catch(() => ({}));
  if (!r.ok || json.status !== "OK") return null;

  const loc = json?.results?.[0]?.geometry?.location;
  if (!loc || typeof loc.lat !== "number" || typeof loc.lng !== "number") return null;
  return { lat: loc.lat, lng: loc.lng };
}

async function fetchAmadeusToken(requestId) {
  const url = getAmadeusTokenUrl();
  const body =
    "grant_type=client_credentials" +
    "&client_id=" + encodeURIComponent(AMADEUS_CLIENT_ID) +
    "&client_secret=" + encodeURIComponent(AMADEUS_CLIENT_SECRET);
  const clientIdLen = AMADEUS_CLIENT_ID.length;
  const secretLen = AMADEUS_CLIENT_SECRET.length;
  const host = getUrlHost(url);

  let r;
  try {
    r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
  } catch (e) {
    console.log(
      "[Hotels TOKEN]",
      "requestId=" + requestId,
      "host=" + host,
      "status=ERR",
      "clientIdLen=" + clientIdLen,
      "secretLen=" + secretLen
    );
    return { ok: false, status: 502, error: "Amadeus auth failed" };
  }

  const responseText = await r.text().catch(() => "");
  console.log(
    "[Hotels TOKEN]",
    "requestId=" + requestId,
    "host=" + host,
    "status=" + r.status,
    "clientIdLen=" + clientIdLen,
    "secretLen=" + secretLen
  );
  if (!r.ok) {
    console.log(
      "[Hotels TOKEN]",
      "requestId=" + requestId,
      "status=FAIL",
      "body=" + String(responseText).slice(0, 300)
    );
  }

  let json = {};
  try {
    json = responseText ? JSON.parse(responseText) : {};
  } catch (_) {
    json = {};
  }
  const token = String(json?.access_token || "").trim();
  if (!r.ok || !token) {
    return { ok: false, status: 502, error: "Amadeus auth failed" };
  }
  return { ok: true, token };
}

async function requireUserId(req, res) {
  // 1) prefer JWT
  const auth = String(req.headers.authorization || "");
  const m = auth.match(/^Bearer\s+(.+)$/i);

  if (m && !JWT_SECRET) {
    res.status(500).json({ ok: false, error: "JWT_SECRET not set" });
    return null;
  }

  if (req.userId && req.userIdVerified) {
    return req.userId;
  }

  if (m) {
    const token = m[1].trim();
    try {
      const { jwtVerify } = await getJose();
      const encoder = new TextEncoder();

      const { payload } = await jwtVerify(token, encoder.encode(JWT_SECRET), {
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });

      const sub = String(payload?.sub || "").trim();
      if (sub) {
        req.userId = sub;
        req.userIdVerified = true;
        return sub;
      }

      res.status(401).json({ ok: false, error: "JWT missing sub" });
      return null;
    } catch (e) {
      console.log("[Auth] jwt verify failed:", e?.message || e);
    }
  }

  // 2) fallback: x-user-id
  const userId = String(req.userId || req.headers["x-user-id"] || "").trim();
  if (!userId) {
    res.status(401).json({ ok: false, error: "Missing auth" });
    return null;
  }
  req.userId = userId;
  req.userIdVerified = false;
  return userId;
}

function requireDb(req, res) {
  if (!dbPool) {
    res.status(500).json({ ok: false, error: "DATABASE_URL not set" });
    return false;
  }
  return true;
}

// ---------------------------------------------
// Sign in with Apple (dev + prod)
// ---------------------------------------------
app.post("/auth/apple", async (req, res) => {
  // DEV MODE
  if (AUTH_MODE !== "prod") {
    const devSub = String(req.body?.devSub || "").trim();
    if (!devSub) {
      return res.status(400).json({ ok: false, error: "Missing devSub" });
    }
    if (devSub.length > 4000) {
      return res.status(400).json({ ok: false, error: "Invalid devSub" });
    }
    if (!JWT_SECRET) {
      return res.status(500).json({ ok: false, error: "Server misconfigured" });
    }

    try {
      const token = await signZippyToken(devSub);
      return res.json({ ok: true, token, mode: "dev" });
    } catch (e) {
      console.warn("Failed to mint dev token:", e?.message || e);
      return res.status(500).json({ ok: false, error: "Server misconfigured" });
    }
  }

  // PROD MODE
  if (!APPLE_CLIENT_ID || !JWT_SECRET) {
    console.warn("Missing APPLE_CLIENT_ID or JWT_SECRET for prod auth");
    return res.status(500).json({ ok: false, error: "Server misconfigured" });
  }

  const identityToken = String(req.body?.identityToken || "").trim();
  if (!identityToken) {
    return res.status(400).json({ ok: false, error: "Missing identityToken" });
  }
  if (identityToken.length > 4000) {
    return res.status(400).json({ ok: false, error: "Invalid identityToken" });
  }

  try {
    const { jwtVerify } = await getJose();
    const jwks = await getAppleJwks();

    const { payload } = await jwtVerify(identityToken, jwks, {
      issuer: APPLE_ISSUER,
      audience: APPLE_CLIENT_ID,
    });

    const appleSub = String(payload?.sub || "").trim();
    if (!appleSub) {
      return res.status(401).json({ ok: false, error: "Invalid identityToken" });
    }

    const token = await signZippyToken(appleSub);
    if (!token) {
      return res.status(500).json({ ok: false, error: "Server misconfigured" });
    }

    return res.json({ ok: true, token, mode: "prod" });
  } catch (e) {
    const reason = e?.code || e?.name || e?.message || "unknown";
    console.warn("Apple identityToken verification failed:", reason);
    return res.status(401).json({ ok: false, error: "Invalid identityToken" });
  }
});

// ---------------------------------------------
// List saved items
// ---------------------------------------------
app.get("/me/saved", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;
  if (!requireDb(req, res)) return;

  const kind = String(req.query.kind || "").trim();

  try {
    const params = [userId];
    let sql = `
      select
        kind,
        external_id as "externalId",
        payload,
        created_at as "createdAt"
      from saved_items
      where user_id = $1
        and deleted_at is null
    `;

    if (kind) {
      params.push(kind);
      sql += ` and kind = $2`;
    }

    sql += ` order by created_at desc limit 200`;

    const { rows } = await dbPool.query(sql, params);
    return res.json({ ok: true, items: rows });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------------------------------------------
// Save (upsert)
// ---------------------------------------------
app.post("/me/saved", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;
  if (!requireDb(req, res)) return;

  const kind = String(req.body?.kind || "").trim();
  const externalId = String(req.body?.externalId || "").trim();
  const payload = req.body?.payload ?? {};

  if (!kind || !externalId) {
    return res.status(400).json({ ok: false, error: "Missing kind or externalId" });
  }
  const payloadCheck = validateSavedPayload(payload);
  if (!payloadCheck.ok) {
    return res.status(400).json({ ok: false, error: payloadCheck.error });
  }

  try {
    await dbPool.query(
      `
      insert into saved_items (user_id, kind, external_id, payload, updated_at, deleted_at)
      values ($1, $2, $3, $4::jsonb, now(), null)
      on conflict (user_id, kind, external_id)
      do update
        set payload = excluded.payload,
            updated_at = now(),
            deleted_at = null
      `,
      [userId, kind, externalId, JSON.stringify(payload)]
    );

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------------------------------------------
// Delete (soft delete)
// ---------------------------------------------
app.delete("/me/saved/:kind/:externalId", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;
  if (!requireDb(req, res)) return;

  const kind = String(req.params.kind || "").trim();
  const externalId = String(req.params.externalId || "").trim();

  try {
    await dbPool.query(
      `
      update saved_items
      set deleted_at = now(),
          updated_at = now()
      where user_id = $1
        and kind = $2
        and external_id = $3
        and deleted_at is null
      `,
      [userId, kind, externalId]
    );

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------------------------------------------
// Start server
// ---------------------------------------------
const port = process.env.PORT || 4001;

app.listen(port, "0.0.0.0", () => {
  console.log("zippy-api listening on port", port);
  console.log("boot ok");
});
