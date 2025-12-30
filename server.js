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

const port = process.env.PORT || 4001;
app.listen(port, "0.0.0.0", () => {
  console.log("zippy-api listening on port", port);
});
