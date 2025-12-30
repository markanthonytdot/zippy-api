const express = require("express");
const { Pool } = require("pg");
const app = express();

app.use(express.json());

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
// Root route (optional)
// ---------------------------------------------
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "zippy-api",
    routes: ["/health", "/health/db"],
  });
});

// ---------------------------------------------
// One-time DB init (you already ran this)
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

      create unique index if not exists uq_saved_items_user_kind_ext
        on saved_items(user_id, kind, external_id)
        where deleted_at is null;
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
  const userId = String(req.headers["x-user-id"] || "").trim();
  if (!userId) {
    res.status(401).json({ ok: false, error: "Missing x-user-id header" });
    return null;
  }
  return userId;
}

// ---------------------------------------------
// List saved items
// ---------------------------------------------
app.get("/me/saved", async (req, res) => {
  const userId = requireUserId(req, res);
  if (!userId) return;

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
