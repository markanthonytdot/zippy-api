const express = require("express");
const { Pool } = require("pg");
const app = express();
const jwt = require("jsonwebtoken");

app.use(express.json());

// ---------------------------------------------
// Basic health
// ---------------------------------------------
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "zippy-api", version: "authdebug-1" });
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
function requireUserId(req, res) {
  // express lowercases header keys
  const auth = String(req.headers.authorization || "");

  // debug (temporary)
  console.log("[AuthDebug] headerKeys=", Object.keys(req.headers));
  console.log("[AuthDebug] authorization=", auth ? auth.slice(0, 24) + "..." : "(none)");

  // 1) prefer JWT
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m) {
    const token = m[1].trim();
    try {
      if (!process.env.JWT_SECRET) {
        res.status(500).json({ ok: false, error: "JWT_SECRET not set" });
        return null;
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        issuer: process.env.JWT_ISSUER || "zippy-api",
        audience: process.env.JWT_AUDIENCE || "zippy-ios",
      });

      const sub = String(decoded?.sub || "").trim();
      if (sub) return sub;

      res.status(401).json({ ok: false, error: "JWT missing sub" });
      return null;
    } catch (e) {
      // if JWT fails, fall back to x-user-id (dev safety)
      console.log("[Auth] jwt verify failed:", e?.message || e);
    }
  }

  // 2) fallback: device id
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

function getAuthUser(req) {
  const auth = String(req.headers.authorization || "");
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m) {
    const tok = m[1].trim();
    return { mode: "jwt", value: tok.slice(0, 12) + "..." };
  }

  const uid = String(req.headers["x-user-id"] || "");
  if (uid) return { mode: "x-user-id", value: uid };

  return { mode: "none", value: "" };
}

// ---------------------------------------------
// Auth (dev stub)
// ---------------------------------------------
app.post("/auth/apple", (req, res) => {
  console.log("[AuthCheck] /auth/apple", getAuthUser(req));

  const mode = String(process.env.AUTH_MODE || "dev").toLowerCase();

  try {
    if (mode !== "dev") {
      return res
        .status(501)
        .json({ ok: false, error: "prod mode not implemented yet" });
    }

    const devSub = String(req.body?.devSub || "dev-user-001");

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ ok: false, error: "JWT_SECRET not set" });
    }

    const token = jwt.sign({ sub: devSub, uid: devSub }, process.env.JWT_SECRET, {
      issuer: process.env.JWT_ISSUER || "zippy-api",
      audience: process.env.JWT_AUDIENCE || "zippy-ios",
      expiresIn: "30d",
    });

    return res.json({ ok: true, token });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message || "auth failed" });
  }
});

// ---------------------------------------------
// List saved items
// ---------------------------------------------
app.get("/me/saved", async (req, res) => {
  console.log("[AuthCheck] /me/saved", getAuthUser(req));

  const userId = requireUserId(req, res);
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
  const userId = requireUserId(req, res);
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
  const userId = requireUserId(req, res);
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
