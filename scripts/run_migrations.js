const path = require("node:path");
const { Pool } = require("pg");
const { databaseSSLForURL } = require("../lib/databaseConfig");
const { discoverMigrations, runMigrations } = require("../lib/migrations");

async function main() {
  const databaseUrl = String(process.env.DATABASE_URL || "").trim();
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required");
  }

  const migrations = discoverMigrations(path.join(__dirname, "..", "migrations"));
  if (migrations.length === 0) throw new Error("No migrations found");

  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: databaseSSLForURL(databaseUrl),
    connectionTimeoutMillis: 10_000,
    max: 1,
  });
  let client;
  try {
    client = await pool.connect();
    console.log(`[migrate] discovered ${migrations.length} migration(s)`);
    await runMigrations({ client, migrations });
    console.log("[migrate] complete");
  } finally {
    client?.release();
    await pool.end();
  }
}

main().catch((error) => {
  console.error(`[migrate] failed: ${error.message}`);
  process.exitCode = 1;
});
