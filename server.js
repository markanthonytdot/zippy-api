const express = require("express");
const { Pool } = require("pg");
const app = express();

// basic health
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "zippy-api" });
});

// database pool
const dbPool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
  : null;

// db health
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

// optional root route (nice to have)
app.get("/", (req, res) => {
  res.json({ ok: true, service: "zippy-api", routes: ["/health", "/health/db"] });
});
app.post("/admin/init", async (req, res) => {
  if (!dbPool) return res.status(500).json({ ok: false, error: "DATABASE_URL not set" });

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

      create index if not exists idx_saved_items_user_kind on saved_items(user_id, kind);
      create index if not exists idx_saved_items_user_updated on saved_items(user_id, updated_at);

      create unique index if not exists uq_saved_items_user_kind_ext
        on saved_items(user_id, kind, external_id)
        where deleted_at is null;
    `);

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});
const port = process.env.PORT || 4001;
app.listen(port, "0.0.0.0", () => {
  console.log("zippy-api listening on port", port);
});
