const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const crypto = require('node:crypto');
const { discoverMigrations, runMigrations } = require('../lib/migrations');
const { preflightAndroidTesterSchema } = require('../lib/androidTesterPreflight');
test('production-baseline migration guard, preflight, upgrade and restart', async t => {
  const connectionString = process.env.PARTNER_TEST_DATABASE_URL;
  assert.ok(connectionString && ['127.0.0.1','localhost','[::1]'].includes(new URL(connectionString).hostname));
  const schema = `android_migration_${crypto.randomBytes(8).toString('hex')}`;
  const pool = new Pool({ connectionString, ssl: false }); const client = await pool.connect();
  t.after(async () => { await client.query(`drop schema ${schema} cascade`); client.release(); await pool.end(); });
  await client.query(`create schema ${schema}`); await client.query(`set search_path=${schema}`);
  const migrations = discoverMigrations(path.join(__dirname, '../migrations'));
  assert.equal(migrations.length, 15);
  await runMigrations({ client, migrations: migrations.slice(0,12), log() {} });
  await client.query('begin read only');
  const before = await preflightAndroidTesterSchema(client, migrations); await client.query('rollback');
  assert.deepEqual(before.pending, ['013_partner_access.sql','014_tester_invitations.sql','015_android_tester_eligibility.sql']);
  await client.query('create table partner_people(id text)');
  await assert.rejects(preflightAndroidTesterSchema(client, migrations), /Untracked tester tables/);
  await client.query('drop table partner_people');
  await runMigrations({ client, migrations, log() {} });
  await runMigrations({ client, migrations, log() {} });
  const after = await preflightAndroidTesterSchema(client, migrations); assert.deepEqual(after.pending, []); assert.equal(after.testerTableCount, 6);
  assert.equal((await client.query('select count(*) from partner_people')).rows[0].count, '0');
  assert.equal((await client.query('select count(*) from partner_verifications')).rows[0].count, '0');
  await client.query("update schema_migrations set filename='015_tester_invitation_confirmation.sql' where filename='015_android_tester_eligibility.sql'");
  await assert.rejects(preflightAndroidTesterSchema(client, migrations), /absent from disk/);
});
test('production migration additions have no copy/import of live identities or sessions', () => {
  const text = ['013_partner_access.sql','014_tester_invitations.sql','015_android_tester_eligibility.sql']
    .map(file => fs.readFileSync(path.join(__dirname, '../migrations', file), 'utf8')).join('\n');
  assert.doesNotMatch(text, /dblink|foreign table|insert into partner_people|insert into partner_verifications|postgres:\/\//i);
});
