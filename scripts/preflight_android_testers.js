const path = require('node:path');
const { Pool } = require('pg');
const { databaseSSLForURL } = require('../lib/databaseConfig');
const { discoverMigrations } = require('../lib/migrations');
const { preflightAndroidTesterSchema } = require('../lib/androidTesterPreflight');
async function main() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: databaseSSLForURL(process.env.DATABASE_URL) });
  const client = await pool.connect();
  try {
    await client.query('begin read only');
    console.log(JSON.stringify(await preflightAndroidTesterSchema(client, discoverMigrations(path.join(__dirname, '../migrations')))));
    await client.query('rollback');
  } finally { client.release(); await pool.end(); }
}
main().catch(() => { console.error('Android tester schema preflight failed; review baseline/ledger compatibility. No migration was applied.'); process.exitCode = 1; });
