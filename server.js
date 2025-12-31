const express = require("express");
const { Pool } = require("pg");
const app = express();

app.use(express.json());

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
  res.json({ ok: true, service: "zippy-api" });
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
