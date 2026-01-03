const express = require("express");
const { Pool } = require("pg");
const app = express();

app.use(express.json());
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

// caches
const placesDetailsCache = makeTtlCache(); // key = placeId

// limiters (tune later)
const placesDetailsLimiter = makeFixedWindowLimiter({
  windowMs: 60 * 1000,
  max: Number(process.env.PLACES_DETAILS_RPM || 30), // per user per minute
});

// Google key (server-only)
const GOOGLE_PLACES_API_KEY = process.env.GOOGLE_PLACES_API_KEY || "";

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

  // rate limit
  const lim = placesDetailsLimiter.allow(`details:${userId}`);
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

    const r = await fetch(url);
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


  // call Google Places Photo
  const url =
    `https://maps.googleapis.com/maps/api/place/photo` +
    `?maxwidth=${encodeURIComponent(String(maxWidth))}` +
    `&photoreference=${encodeURIComponent(ref)}` +
    `&key=${encodeURIComponent(apiKey)}`;

  try {
    const r = await fetch(url, { redirect: "follow" });

    if (!r.ok) {
      const text = await r.text().catch(() => "");
      return res.status(502).json({
        ok: false,
        error: `Google photo fetch failed (${r.status})`,
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


app.get("/v1/places/details", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;

  const placeId = String(req.query.placeId || "").trim();

  return res.json({
    ok: true,
    stub: true,
    endpoint: "details",
    userId,
    placeId: placeId ? "[provided]" : "",
  });
});

app.post("/v1/places/eta", async (req, res) => {
  const userId = await requireUserId(req, res);
  if (!userId) return;

  return res.json({
    ok: true,
    stub: true,
    endpoint: "eta",
    userId,
    bodyKeys: Object.keys(req.body || {}),
  });
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

function enforcePhotoLimits(userId, plan) {
  const minute = nowMinuteKey();
  const day = todayKey();

  const rpmFree = getEnvInt("PLACES_PHOTO_RPM_FREE", 1);
  const rpmPaid = getEnvInt("PLACES_PHOTO_RPM_PAID", 60);
  const dailyFree = getEnvInt("PLACES_PHOTO_DAILY_FREE", 1);
  const dailyPaid = getEnvInt("PLACES_PHOTO_DAILY_PAID", 120);

  const rpmLimit = plan === "paid" ? rpmPaid : rpmFree;
  const dailyLimit = plan === "paid" ? dailyPaid : dailyFree;

  const minuteKey = `${userId}:${minute}`;
  const dayKey = `${userId}:${day}`;

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

function getCachedPhoto(cacheKey) {
  const hit = photoCache.get(cacheKey);
  if (!hit) return null;
  if (Date.now() > hit.expiresAt) {
    photoCache.delete(cacheKey);
    return null;
  }
  return hit;
}

// ---------------------------------------------
// Helpers
// ---------------------------------------------
async function requireUserId(req, res) {
  // 1) prefer JWT
  const auth = String(req.headers.authorization || "");
  const m = auth.match(/^Bearer\s+(.+)$/i);

  if (m) {
    const token = m[1].trim();
    try {
      if (!JWT_SECRET) {
        res.status(500).json({ ok: false, error: "JWT_SECRET not set" });
        return null;
      }

      const { jwtVerify } = await getJose();
      const encoder = new TextEncoder();

      const { payload } = await jwtVerify(token, encoder.encode(JWT_SECRET), {
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });

      const sub = String(payload?.sub || "").trim();
      if (sub) return sub;

      res.status(401).json({ ok: false, error: "JWT missing sub" });
      return null;
    } catch (e) {
      console.log("[Auth] jwt verify failed:", e?.message || e);
    }
  }

  // 2) fallback: x-user-id
  const userId = String(req.headers["x-user-id"] || "").trim();
  if (!userId) {
    res.status(401).json({ ok: false, error: "Missing auth" });
    return null;
  }
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
});
// proof
