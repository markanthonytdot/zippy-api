const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { once } = require('node:events');
const { discoverMigrations, runMigrations, migrationChecksum } = require('../lib/migrations');
const { createDemoFeedbackService, parseFilters, LIKELIHOODS } = require('../lib/demoFeedback');
const { CLARITY, QUESTIONS, validateCombinedSubmission, summarizeCombined } = require('../lib/combinedDemoFeedback');
const { createDemoFeedbackPublicRouter } = require('../lib/demoFeedbackRoutes');
const { createPackageFeedbackService } = require('../lib/packageFeedback');
const { createFeedbackReadBridgeRouter } = require('../lib/feedbackReadBridge');
const { createAdminDashboardRouter } = require('../lib/adminDashboard');
const production = require('./fixtures/combined-feedback-production-migrations.json');
const version = 'combined_demo_v3';
const answer = (extra = {}) => ({ request_id: crypto.randomUUID(), survey_version: version, clarity: 'Very clear', use_likelihood: 'Definitely', booked_travel_last_12_months: true, source: 'qa-combined-demo', website: '', ...extra });
const migrations = discoverMigrations(require('node:path').join(__dirname, '../migrations'));

test('new survey validates all 32 choices and exact question IDs without accepting old meanings', () => {
  let count = 0;
  for (const clarity of CLARITY) for (const use_likelihood of LIKELIHOODS) for (const booked_travel_last_12_months of [true, false]) {
    assert.equal(validateCombinedSubmission(answer({ clarity, use_likelihood, booked_travel_last_12_months })).clarity, clarity); count++;
  }
  assert.equal(count, 32); assert.deepEqual(QUESTIONS.map(q => q.id), ['clarity', 'use_likelihood', 'booked_travel_last_12_months']);
  for (const change of [{ survey_version: undefined }, { survey_version: 'multiple_choice_v2' }, { clarity: 'Clear' }, { clarity: ['Very clear'] }, { clarity: undefined }, { use_likelihood: 'Maybe' }, { use_likelihood: undefined }, { booked_travel_last_12_months: 'yes' }, { booked_travel_last_12_months: undefined }, { source: 'person@example.invalid' }, { request_id: 'bad' }, { website: 'spam' }]) assert.throws(() => validateCombinedSubmission(answer(change)), e => e.status === 400);
  assert.equal(validateCombinedSubmission(answer({ source: undefined })).source, 'direct');
  const uppercaseId = crypto.randomUUID().toUpperCase(); assert.equal(validateCombinedSubmission(answer({ request_id: uppercaseId })).request_id, uppercaseId.toLowerCase());
  for (const query of [{ survey_version: 'unknown' }, { survey_version: version, recent: 'yes' }, { clarity: 'Very clear' }, { survey_version: version, booked: 'maybe' }]) assert.throws(() => parseFilters(query));
});

test('validation segment uses matching rows and all booking-question respondents', () => {
  const summary = summarizeCombined([
    { source: 'a', clarity: 'Very clear', use_likelihood: 'Definitely', booked_travel_last_12_months: true, count: 2 },
    { source: 'a', clarity: 'Somewhat clear', use_likelihood: 'Probably not', booked_travel_last_12_months: true, count: 1 },
    { source: 'a', clarity: 'Not clear at all', use_likelihood: 'Probably', booked_travel_last_12_months: false, count: 7 },
  ]).overall;
  assert.deepEqual(summary.validation, { count: 2, percent: 20, denominator: 10 });
  assert.equal(summary.positive.percent, 90); assert.equal(summary.booked.yes.percent, 30);
  assert.deepEqual(summarizeCombined([]).overall.validation, { count: 0, percent: null, denominator: 0 });
});

test('019 is additive and preserves the deployed 001–018 checksums', () => {
  assert.deepEqual(migrations.slice(0, 18).map(({ filename, checksum }) => ({ filename, checksum })), production.migrations);
  assert.deepEqual(migrations.map(m => m.version), Array.from({ length: 19 }, (_, i) => i + 1));
  assert.equal(migrations[18].filename, '019_combined_demo_feedback.sql');
  assert.doesNotMatch(migrations[18].sql, /\b(?:alter|update|delete|truncate|insert|drop)\b/i);
});

const databaseUrl = process.env.DEMO_FEEDBACK_TEST_DATABASE_URL;
test('combined poll migration, PostgreSQL/HTTP, history and exports', { skip: !databaseUrl }, async t => {
  const url = new URL(databaseUrl); assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname));
  const { Pool, Client } = require('pg'); const express = require('express');
  const root = new Client({ connectionString: databaseUrl, ssl: false }); await root.connect();
  const name = `combined_feedback_${crypto.randomBytes(8).toString('hex')}`; await root.query(`create database ${name}`);
  url.pathname = '/' + name;
  const pool = new Pool({ connectionString: url.toString(), ssl: false }); const migrationClient = await pool.connect();
  let server;
  t.after(async () => { if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } migrationClient.release(); await pool.end(); await root.query(`drop database ${name}`); await root.end(); });
  const run = selected => runMigrations({ client: migrationClient, migrations: selected, log() {} });
  await run(migrations.slice(0, 18));
  for (const comprehension of [null, 'natural_language_flight_search']) await pool.query("insert into demo_feedback_responses(id,request_id,understanding,likelihood,reason,recent_flight_shopper,source,comprehension_choice,submitted_at,created_at,updated_at) values($1,$2,'Unchanged old answer','Probably','Original reason',true,'qa-combined-demo',$3,'2026-09-10','2026-09-10','2026-09-10')", [crypto.randomUUID(), crypto.randomUUID(), comprehension]);
  await pool.query("insert into package_feedback_responses(id,request_id,likelihood,usefulness,source) values($1,$2,'Definitely','Yes','qa-combined-demo')", [crypto.randomUUID(), crypto.randomUUID()]);
  await pool.query("insert into package_feedback_clicks(event_id,source) values($1,'qa-combined-demo')", [crypto.randomUUID()]);
  async function snapshot() {
    const result = {};
    for (const table of ['demo_feedback_responses', 'package_feedback_responses', 'package_feedback_clicks']) {
      const rows = (await pool.query(`select to_jsonb(t)::text as row from ${table} t order by row`)).rows;
      result[table] = { count: rows.length, sha256: crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex') };
    }
    return result;
  }
  const before = await snapshot();
  const ledgerBefore = (await pool.query('select * from schema_migrations order by filename')).rows;
  await t.test('failed 019 rolls back and valid upgrade preserves every historical row and ledger', async () => {
    const sql = migrations[18].sql + '\nselect 1/0;';
    await assert.rejects(run([...migrations.slice(0, 18), { ...migrations[18], sql, checksum: migrationChecksum(Buffer.from(sql)) }]), e => e.code === '22012');
    assert.equal((await pool.query("select to_regclass('combined_demo_feedback_responses') as table_name")).rows[0].table_name, null);
    assert.deepEqual((await pool.query('select * from schema_migrations order by filename')).rows, ledgerBefore); assert.deepEqual(await snapshot(), before);
    await run(migrations); assert.deepEqual(await snapshot(), before);
    assert.deepEqual((await pool.query('select * from schema_migrations order by filename')).rows.slice(0, 18), ledgerBefore);
    assert.equal((await pool.query('select count(*) from combined_demo_feedback_responses')).rows[0].count, '0');
    const ledgerAfter = (await pool.query('select * from schema_migrations order by filename')).rows; await run(migrations);
    assert.deepEqual((await pool.query('select * from schema_migrations order by filename')).rows, ledgerAfter);
    for (const op of ['select', 'insert', 'update', 'delete']) assert.equal((await pool.query("select has_table_privilege('public','combined_demo_feedback_responses',$1) as allowed", [op])).rows[0].allowed, false);
  });
  let clock = Date.now(); const flight = createDemoFeedbackService({ dbPool: pool, secret: 'local-combined-secret', now: () => clock });
  const packages = createPackageFeedbackService({ dbPool: pool, secret: 'local-combined-secret' });
  const legacyReportBefore = await flight.report({}); const packageReportBefore = await packages.report({});
  const app = express(); app.use(express.json()); app.use(express.urlencoded({ extended: false }));
  app.use('/v1/demo-feedback', createDemoFeedbackPublicRouter({ service: flight, allowedOrigins: 'http://localhost:4318' }));
  app.use('/admin', createAdminDashboardRouter({ dbPool: pool, adminSecret: 'local-only-admin', sessionSecret: 'local-only-session', demoFeedbackService: flight, packageFeedbackService: packages }));
  const bridgeSecret = 'local-only-feedback-bridge-credential-123456789';
  app.use('/internal/feedback-read', createFeedbackReadBridgeRouter({ secret: bridgeSecret, flight, packages }));
  server = app.listen(0, '127.0.0.1'); await once(server, 'listening'); const base = `http://127.0.0.1:${server.address().port}`;
  const post = body => fetch(base + '/v1/demo-feedback', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:4318' }, body: JSON.stringify(body) });
  const login = await fetch(base + '/admin/session', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'secret=local-only-admin', redirect: 'manual' });
  assert.equal(login.status, 303); const cookie = login.headers.get('set-cookie').split(';')[0];
  const read = async query => { const response = await fetch(base + '/admin/api/demo-feedback?' + new URLSearchParams(query), { headers: { Cookie: cookie } }); assert.equal(response.status, 200); return response.json(); };
  await t.test('all 32 option combinations persist with version, exact answers and metadata', async () => {
    assert.deepEqual(await snapshot(), before); assert.equal((await read({ survey_version: version })).overall.total, 0);
    for (const clarity of CLARITY) for (const use_likelihood of LIKELIHOODS) for (const booked_travel_last_12_months of [true, false]) {
      clock += 16 * 60 * 1000;
      const payload = answer({ clarity, use_likelihood, booked_travel_last_12_months });
      assert.equal((await post(payload)).status, 201); assert.equal((await post({ ...payload, request_id: payload.request_id.toUpperCase() })).status, 201);
      assert.equal((await post({ ...payload, booked_travel_last_12_months: !booked_travel_last_12_months })).status, 409);
      const row = (await pool.query('select * from combined_demo_feedback_responses where request_id=$1', [payload.request_id])).rows[0];
      for (const key of ['survey_version', 'clarity', 'use_likelihood', 'booked_travel_last_12_months', 'source']) assert.equal(row[key], payload[key]);
      for (const key of ['id', 'request_id', 'submitted_at', 'created_at', 'updated_at']) assert.ok(row[key]);
    }
    assert.equal((await pool.query('select count(*) from combined_demo_feedback_responses')).rows[0].count, '32');
    const stored = (await pool.query('select id from combined_demo_feedback_responses limit 1')).rows[0];
    for (const [field, value] of [['survey_version', 'wrong'], ['clarity', 'Clear'], ['use_likelihood', 'Maybe'], ['booked_travel_last_12_months', null]]) await assert.rejects(pool.query(`update combined_demo_feedback_responses set ${field}=$1 where id=$2`, [value, stored.id]), e => ['23514', '23502'].includes(e.code));
    assert.deepEqual(await snapshot(), before); assert.deepEqual(await flight.report({}), legacyReportBefore); assert.deepEqual(await packages.report({}), packageReportBefore);
  });
  await t.test('current summaries, historical separation, filters and cohort calculations', async () => {
    const current = await read({ survey_version: version });
    assert.equal(current.overall.total, 32); assert.deepEqual(current.overall.validation, { count: 8, percent: 25, denominator: 32 });
    assert.equal(current.overall.booked.yes.percent, 50); assert.equal(current.overall.positive.percent, 50);
    assert.deepEqual(current.totals, { all: 35, current: 32, free_text_v1: 1, multiple_choice_v2: 1, package_v1: 1 });
    for (const value of Object.values(current.overall.clarity)) assert.deepEqual(value, { count: 8, percent: 25 });
    for (const value of Object.values(current.overall.likelihoods)) assert.deepEqual(value, { count: 8, percent: 25 });
    for (const survey_version of ['free_text_v1', 'multiple_choice_v2']) { const report = await read({ survey_version }); assert.equal(report.overall.total, 1); assert.equal(report.rows[0].survey_version, survey_version); }
    const filter = await read({ survey_version: version, clarity: 'Very clear', booked: 'yes', likelihood: 'Probably' }); assert.equal(filter.overall.total, 1); assert.equal(filter.overall.validation.percent, 100); assert.equal(filter.totals.all, 35);
    const empty = await read({ survey_version: version, source: 'none' }); assert.equal(empty.overall.validation.percent, null); assert.equal(empty.totals.all, 0);
    assert.equal((await read({ survey_version: version, from: '2000-01-01', to: '2000-01-01' })).overall.total, 0);
  });
  await t.test('version validation, anonymous denial, original login, bridge and filtered exports', async () => {
    clock += 16 * 60 * 1000;
    for (const extra of [{ survey_version: 'unknown' }, { survey_version: null }, { booked_travel_last_12_months: 'yes' }, { clarity: undefined }]) assert.equal((await post(answer(extra))).status, 400);
    for (const path of ['/admin/api/demo-feedback?survey_version=' + version, '/admin/api/demo-feedback/export.csv?survey_version=' + version]) assert.equal((await fetch(base + path)).status, 401);
    assert.equal((await fetch(base + '/admin/demo-feedback', { redirect: 'manual' })).status, 302);
    assert.equal((await fetch(base + '/v1/demo-feedback')).status, 405);
    const bridge = await fetch(base + '/internal/feedback-read/demo-feedback?survey_version=' + version, { headers: { 'x-zippi-feedback-read': bridgeSecret } }); assert.equal(bridge.status, 200); assert.equal((await bridge.json()).overall.total, 32);
    const currentCsv = await fetch(base + '/internal/feedback-read/demo-feedback/export.csv?survey_version=' + version, { headers: { 'x-zippi-feedback-read': bridgeSecret } }); assert.equal(currentCsv.status, 200); const text = await currentCsv.text();
    assert.equal(text.trim().split('\r\n').length, 33); assert.ok(text.includes('"Survey version","Request ID"')); assert.ok(text.includes('"clarity","Very clear","use_likelihood","Definitely","booked_travel_last_12_months","Yes"'));
    const legacy = await fetch(base + '/admin/api/demo-feedback/export.csv?survey_version=free_text_v1', { headers: { Cookie: cookie } }); const oldText = await legacy.text(); assert.equal(oldText.trim().split('\r\n').length, 2); assert.ok(oldText.includes('Unchanged old answer')); assert.ok(oldText.includes('Original reason')); assert.ok(oldText.includes('free_text_v1'));
    const oldCsv = await fetch(base + '/admin/api/demo-feedback/export.csv', { headers: { Cookie: cookie } }); assert.ok(!(await oldCsv.text()).includes('Clarity question ID'));
    assert.deepEqual(await snapshot(), before);
  });
  await t.test('current CSV streams all pages while reports stay paginated', async () => {
    for (let i = 0; i < 21; i++) { clock += 16 * 60 * 1000; assert.equal((await post(answer())).status, 201); }
    const first = await read({ survey_version: version }); const second = await read({ survey_version: version, page: '2' }); assert.equal(first.rows.length, 50); assert.equal(second.rows.length, 3); assert.equal(first.pages, 2);
    const exported = await fetch(base + '/admin/api/demo-feedback/export.csv?survey_version=' + version + '&page=2', { headers: { Cookie: cookie } }); assert.equal((await exported.text()).trim().split('\r\n').length, 54);
    assert.deepEqual(await snapshot(), before);
  });
});
