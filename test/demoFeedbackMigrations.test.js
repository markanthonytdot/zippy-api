const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { discoverMigrations, runMigrations, migrationChecksum } = require('../lib/migrations');
const production = require('./fixtures/demo-feedback-production-migrations.json');
const migrations = discoverMigrations(path.join(__dirname, '../migrations'));
const feedbackNames = ['016_demo_feedback.sql', '017_demo_feedback_comprehension.sql'];

test('feedback follows the exact production migration history with unique consecutive numbers', () => {
  assert.deepEqual(migrations.slice(0, 15).map(({ filename, checksum }) => ({ filename, checksum })), production.migrations);
  assert.deepEqual(migrations.slice(15).map(m => m.filename), feedbackNames);
  assert.deepEqual(migrations.map(m => m.version), Array.from({ length: 17 }, (_, i) => i + 1));
});

const databaseUrl = process.env.DEMO_FEEDBACK_TEST_DATABASE_URL;
test('feedback migration runner against production-history PostgreSQL databases', { skip: !databaseUrl }, async t => {
  const url = new URL(databaseUrl);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only isolated loopback PostgreSQL is allowed');
  const { Client } = require('pg');
  const root = new Client({ connectionString: databaseUrl, ssl: false });
  await root.connect();
  t.after(() => root.end());
  async function withDatabase(label, body) {
    const name = `feedback_migrations_${label}_${crypto.randomBytes(6).toString('hex')}`;
    await root.query(`create database ${name}`);
    const isolated = new URL(url); isolated.pathname = `/${name}`;
    const client = new Client({ connectionString: isolated.toString(), ssl: false });
    try { await client.connect(); await body(client); }
    finally { await client.end(); await root.query(`drop database ${name}`); }
  }
  async function run(client, selected = migrations) {
    const logs = [];
    await runMigrations({ client, migrations: selected, log: line => logs.push(line) });
    return logs;
  }
  const ledger = async client => (await client.query('select * from schema_migrations order by filename')).rows;
  async function snapshot(client) {
    const tables = (await client.query("select tablename from pg_tables where schemaname='public' and tablename not like 'demo_feedback_%' and tablename <> 'schema_migrations' order by tablename")).rows;
    const rows = {};
    for (const { tablename } of tables) rows[tablename] = (await client.query(`select to_jsonb(t)::text as value from "${tablename}" t order by value`)).rows;
    const columns = (await client.query("select table_name,column_name,data_type,is_nullable,column_default from information_schema.columns where table_schema='public' and table_name not like 'demo_feedback_%' order by table_name,ordinal_position")).rows;
    const constraints = (await client.query("select c.relname,con.conname,pg_get_constraintdef(con.oid) as definition from pg_constraint con join pg_class c on c.oid=con.conrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname not like 'demo_feedback_%' order by c.relname,con.conname")).rows;
    const indexes = (await client.query("select tablename,indexname,indexdef from pg_indexes where schemaname='public' and tablename not like 'demo_feedback_%' order by tablename,indexname")).rows;
    return { rows, columns, constraints, indexes };
  }
  async function seedProductionShape(client) {
    const id = crypto.randomUUID();
    await client.query("insert into partner_people(id,email,organization_id,starts_at,expires_at) values($1,'local-migration-test@example.invalid','d64dfe7a-3058-4e43-9283-182f60b08baa','2026-09-01','2026-10-01')", [id]);
    await client.query("insert into tester_invitations(id,person_id,platform,play_eligibility,play_eligibility_actor) values($1,$2,'android','confirmed','local-migration-test')", [crypto.randomUUID(), id]);
  }
  async function assertFeedbackSchema(client) {
    const columns = (await client.query("select column_name from information_schema.columns where table_schema='public' and table_name='demo_feedback_responses' order by ordinal_position")).rows.map(r => r.column_name);
    assert.deepEqual(columns, ['id','request_id','understanding','likelihood','reason','recent_flight_shopper','source','submitted_at','created_at','updated_at','comprehension_choice']);
    const indexes = (await client.query("select indexname from pg_indexes where schemaname='public' and tablename like 'demo_feedback_%' order by indexname")).rows.map(r => r.indexname);
    assert.deepEqual(indexes, ['demo_feedback_rate_expiry_idx','demo_feedback_rate_limits_pkey','demo_feedback_responses_pkey','demo_feedback_responses_request_id_key','demo_feedback_source_idx','demo_feedback_submitted_idx']);
    const unique = crypto.randomUUID();
    const insert = `insert into demo_feedback_responses(id,request_id,likelihood,recent_flight_shopper,comprehension_choice) values($1,$2,'Definitely',true,'natural_language_flight_search') returning *`;
    const row = (await client.query(insert, [crypto.randomUUID(), unique])).rows[0];
    assert.equal(row.understanding, ''); assert.equal(row.reason, ''); assert.equal(row.source, 'direct');
    await assert.rejects(client.query(insert, [crypto.randomUUID(), unique]), error => error.code === '23505');
    for (const [field, value] of [['comprehension_choice','invalid'],['understanding','x'.repeat(2001)],['reason','x'.repeat(2001)],['likelihood','Maybe'],['source','person@example.invalid']]) {
      await assert.rejects(client.query(`update demo_feedback_responses set ${field}=$1 where id=$2`, [value, row.id]), error => error.code === '23514');
    }
    await assert.rejects(client.query('update demo_feedback_responses set recent_flight_shopper=null where id=$1', [row.id]), error => error.code === '23502');
    for (const table of ['demo_feedback_responses','demo_feedback_rate_limits']) {
      for (const operation of ['SELECT','INSERT','UPDATE','DELETE']) {
        assert.equal((await client.query('select has_table_privilege(\'public\',$1,$2) as allowed', [table, operation])).rows[0].allowed, false);
      }
    }
    const role = `feedback_anon_${crypto.randomBytes(6).toString('hex')}`;
    await root.query(`create role ${role} nologin`);
    try {
      await client.query(`set role ${role}`);
      for (const table of ['demo_feedback_responses','demo_feedback_rate_limits']) await assert.rejects(client.query(`select * from ${table}`), error => error.code === '42501');
    } finally { await client.query('reset role'); await root.query(`drop role ${role}`); }
  }
  await t.test('clean database applies 001–017 and a rerun only verifies completed entries', () => withDatabase('fresh', async client => {
    const logs = await run(client);
    assert.deepEqual(logs, migrations.map(m => `[migrate] applied ${m.filename}`));
    const before = await ledger(client); assert.equal(before.length, 17);
    assert.deepEqual(await run(client), migrations.map(m => `[migrate] verified ${m.filename}`));
    assert.deepEqual(await ledger(client), before);
    await assertFeedbackSchema(client);
  }));
  await t.test('existing production schema upgrades without changing applied history, data or unrelated schema', () => withDatabase('upgrade', async client => {
    await run(client, migrations.slice(0, 15)); await seedProductionShape(client);
    const beforeLedger = await ledger(client); const before = await snapshot(client);
    const logs = await run(client);
    assert.deepEqual(logs.slice(0, 15), migrations.slice(0, 15).map(m => `[migrate] verified ${m.filename}`));
    assert.deepEqual(logs.slice(15), feedbackNames.map(name => `[migrate] applied ${name}`));
    assert.deepEqual((await ledger(client)).slice(0, 15), beforeLedger);
    assert.deepEqual(await snapshot(client), before);
    assert.equal((await client.query('select count(*) from demo_feedback_responses')).rows[0].count, '0');
    await assertFeedbackSchema(client);
    const after = await ledger(client); await run(client); assert.deepEqual(await ledger(client), after);
  }));
  for (const failedVersion of [16, 17]) {
    await t.test(`failure inside migration ${failedVersion} rolls back DDL and ledger, then safely resumes`, () => withDatabase(`fail${failedVersion}`, async client => {
      await run(client, migrations.slice(0, 15)); await seedProductionShape(client);
      const baseline = await snapshot(client); const priorLedger = await ledger(client);
      const broken = migrations.map(m => {
        if (m.version !== failedVersion) return m;
        const sql = `${m.sql}\nselect 1/0;\n`;
        return { ...m, sql, checksum: migrationChecksum(Buffer.from(sql)) };
      });
      await assert.rejects(run(client, broken), error => error.code === '22012');
      assert.equal((await ledger(client)).length, failedVersion - 1);
      assert.deepEqual((await ledger(client)).slice(0, 15), priorLedger);
      assert.deepEqual(await snapshot(client), baseline);
      if (failedVersion === 16) {
        assert.equal((await client.query("select to_regclass('demo_feedback_responses') as responses,to_regclass('demo_feedback_rate_limits') as limits")).rows[0].responses, null);
        assert.equal((await client.query("select to_regclass('demo_feedback_rate_limits') as limits")).rows[0].limits, null);
      } else {
        assert.equal((await client.query("select count(*) from information_schema.columns where table_schema='public' and table_name='demo_feedback_responses' and column_name='comprehension_choice'")).rows[0].count, '0');
        const id = crypto.randomUUID();
        await client.query("insert into demo_feedback_responses(id,request_id,understanding,likelihood,reason,recent_flight_shopper) values($1,$2,'Existing local answer','Probably','Existing local reason',true)", [id, crypto.randomUUID()]);
        const oldRow = (await client.query('select * from demo_feedback_responses where id=$1', [id])).rows[0];
        await assert.rejects(client.query("update demo_feedback_responses set understanding='' where id=$1", [id]), error => error.code === '23514');
        await run(client);
        const next = (await client.query('select * from demo_feedback_responses where id=$1', [id])).rows[0];
        assert.equal(next.comprehension_choice, null); delete next.comprehension_choice; assert.deepEqual(next, oldRow);
      }
      const logs = await run(client);
      if (failedVersion === 16) assert.deepEqual(logs.slice(15), feedbackNames.map(name => `[migrate] applied ${name}`));
      assert.equal((await ledger(client)).length, 17);
      assert.deepEqual(await snapshot(client), baseline);
      assert.deepEqual(await run(client), migrations.map(m => `[migrate] verified ${m.filename}`));
    }));
  }
});
