const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');
const { discoverMigrations, runMigrations, migrationChecksum } = require('../lib/migrations');
const { createDemoFeedbackService, parseFilters, LIKELIHOODS } = require('../lib/demoFeedback');
const { CLARITY, QUESTIONS: V3_QUESTIONS } = require('../lib/combinedDemoFeedback');
const { QUESTIONS, OPTIONAL_COMMENT, validateV4Submission } = require('../lib/combinedDemoV4Feedback');
const { createPackageFeedbackService } = require('../lib/packageFeedback');
const { createDemoFeedbackPublicRouter, createDemoFeedbackAdminRouter } = require('../lib/demoFeedbackRoutes');
const { createFeedbackReadBridgeRouter } = require('../lib/feedbackReadBridge');
const migrations = discoverMigrations(path.join(__dirname, '../migrations'));
const version = 'combined_demo_v4';
const answer = (extra = {}) => ({ request_id: crypto.randomUUID(), survey_version: version, clarity: 'Very clear', use_likelihood: 'Definitely', booked_travel_last_12_months: true, source: 'test', website: '', ...extra });

test('v4 freezes v3 source/schema and changes only the version-specific question wording', () => {
  assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, '../lib/combinedDemoFeedback.js'))).digest('hex'), '379d5d04614e157a5e2e64b614c5be437084d11bed476b49471543f64436de0a');
  assert.equal(migrations[18].checksum, '755e2097ceb0fbe292444054d1e9947c9603b4cf6de5c910707e844de9e58e0d');
  assert.deepEqual(migrations.map(m => m.version), Array.from({ length: 20 }, (_, i) => i + 1));
  assert.doesNotMatch(migrations[19].sql, /\b(?:alter|update|delete|truncate|insert|drop)\b/i);
  assert.deepEqual(QUESTIONS[0], V3_QUESTIONS[0]); assert.deepEqual(QUESTIONS[2], V3_QUESTIONS[2]);
  assert.equal(QUESTIONS[1].id, V3_QUESTIONS[1].id);
  assert.equal(QUESTIONS[1].text, 'If this feature were available on a travel website or app you already use, how likely would you be to use it?');
  assert.equal(V3_QUESTIONS[1].text, 'Based on what you saw, how likely would you be to use Zippi when planning your next trip?');
  assert.deepEqual(QUESTIONS[1].options, ['Definitely', 'Probably', 'Probably not', 'Definitely not']);
  assert.deepEqual(OPTIONAL_COMMENT, { id: 'optional_comment', text: "Anything else you'd like to share?", optional: true, maxLength: 2000 });
});

test('v4 accepts every structured combination with no comment and validates optional text', () => {
  let combinations = 0;
  for (const clarity of CLARITY) for (const use_likelihood of LIKELIHOODS) for (const booked_travel_last_12_months of [true, false]) {
    const data = validateV4Submission(answer({ clarity, use_likelihood, booked_travel_last_12_months }));
    assert.equal(data.optional_comment, ''); combinations++;
  }
  assert.equal(combinations, 32);
  for (const optional_comment of ['', ' \t\n ', undefined]) assert.equal(validateV4Submission(answer({ optional_comment })).optional_comment, '');
  assert.equal(validateV4Submission(answer({ optional_comment: '  My thought\nAnother line.\t ' })).optional_comment, 'My thought\nAnother line.');
  assert.equal(validateV4Submission(answer({ optional_comment: 'a'.repeat(2000) })).optional_comment.length, 2000);
  for (const optional_comment of [null, false, {}, [], 'a'.repeat(2001), 'unsafe\u0000text', '\u0008', '\u007f']) assert.throws(() => validateV4Submission(answer({ optional_comment })), error => error.status === 400 && error.code === 'invalid_optional_comment');
  for (const extra of [{ survey_version: 'combined_demo_v3' }, { clarity: 'Clear' }, { use_likelihood: 'Maybe' }, { booked_travel_last_12_months: 'Yes' }, { source: 'unsafe@source' }, { request_id: 'invalid' }, { website: 'spam' }]) assert.throws(() => validateV4Submission(answer(extra)), error => error.status === 400);
  for (const survey_version of [version, 'combined_demo_v3']) assert.equal(parseFilters({ survey_version, clarity: 'Very clear', booked: 'yes' }).booked, 'yes');
  for (const query of [{ survey_version: version, recent: 'yes' }, { survey_version: version, booked: 'invalid' }, { survey_version: version, from: '2026-02-31' }, { survey_version: 'combined_demo_v5' }]) assert.throws(() => parseFilters(query), error => error.status === 400);
});

const databaseUrl = process.env.DEMO_FEEDBACK_TEST_DATABASE_URL;
test('v4 PostgreSQL upgrade, atomic storage, report filters and backward-compatible exports', { skip: !databaseUrl }, async t => {
  const url = new URL(databaseUrl);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only isolated local PostgreSQL is permitted');
  const { Client, Pool } = require('pg'); const express = require('express');
  const root = new Client({ connectionString: databaseUrl, ssl: false }); await root.connect();
  const database = 'combined_v4_' + crypto.randomBytes(8).toString('hex');
  await root.query(`create database ${database}`); url.pathname = '/' + database;
  const pool = new Pool({ connectionString: url.toString(), ssl: false });
  const migrationClient = await pool.connect(); let server;
  t.after(async () => { if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } migrationClient.release(); await pool.end(); await root.query(`drop database ${database}`); await root.end(); });
  const run = selected => runMigrations({ client: migrationClient, migrations: selected, log() {} });
  await run(migrations.slice(0, 19));
  let clock = Date.now();
  const service = createDemoFeedbackService({ dbPool: pool, secret: 'local-v4-only', now: () => clock });
  const packages = createPackageFeedbackService({ dbPool: pool, secret: 'local-v4-only' });
  for (const choice of [null, 'natural_language_flight_search']) await pool.query("insert into demo_feedback_responses(id,request_id,understanding,likelihood,reason,recent_flight_shopper,source,comprehension_choice) values($1,$2,'Original words','Probably','Unchanged reason',true,'direct',$3)", [crypto.randomUUID(), crypto.randomUUID(), choice]);
  await pool.query("insert into package_feedback_responses(id,request_id,likelihood,usefulness,comment,source) values($1,$2,'Definitely','Yes','Old package comment','direct')", [crypto.randomUUID(), crypto.randomUUID()]);
  await pool.query("insert into package_feedback_clicks(event_id,source) values($1,'direct')", [crypto.randomUUID()]);
  const originalV3 = [answer({ survey_version: 'combined_demo_v3', source: 'test' }), answer({ survey_version: 'combined_demo_v3', source: 'direct', use_likelihood: 'Probably' }), answer({ survey_version: 'combined_demo_v3', source: 'direct', clarity: 'Somewhat clear', booked_travel_last_12_months: false })];
  for (const payload of originalV3) await service.submit(payload, 'v3-fixture');
  const protectedTables = ['demo_feedback_responses', 'package_feedback_responses', 'package_feedback_clicks', 'combined_demo_feedback_responses'];
  async function snapshot() {
    const tables = {};
    for (const table of protectedTables) {
      const rows = (await pool.query(`select to_jsonb(t)::text as row from ${table} t order by row`)).rows;
      tables[table] = { count: rows.length, sha256: crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex') };
    }
    return tables;
  }
  async function csv(source, filters) { let result = ''; for await (const chunk of source.exportCsv(filters)) result += chunk; return result; }
  async function protectedExports() {
    const result = {};
    for (const survey_version of ['', 'free_text_v1', 'multiple_choice_v2', 'combined_demo_v3']) result[survey_version || 'unversioned'] = await csv(service, { survey_version });
    result.package = await csv(packages, {}); return result;
  }
  const before = await snapshot(); const exportsBefore = await protectedExports();
  const ledgerBefore = (await pool.query('select * from schema_migrations order by filename')).rows;

  await t.test('migration 020 rolls back on failure, starts empty and preserves old rows, ledger and CSV bytes', async () => {
    const brokenSql = migrations[19].sql + '\nselect 1/0;';
    await assert.rejects(run([...migrations.slice(0, 19), { ...migrations[19], sql: brokenSql, checksum: migrationChecksum(Buffer.from(brokenSql)) }]), error => error.code === '22012');
    assert.deepEqual((await pool.query("select to_regclass('combined_demo_v4_feedback_responses') as responses,to_regclass('combined_demo_v4_feedback_comments') as comments")).rows[0], { responses: null, comments: null });
    assert.deepEqual((await pool.query('select * from schema_migrations order by filename')).rows, ledgerBefore);
    await run(migrations); assert.deepEqual(await snapshot(), before); assert.deepEqual(await protectedExports(), exportsBefore);
    const ledgerAfter = (await pool.query('select * from schema_migrations order by filename')).rows;
    assert.deepEqual(ledgerAfter.slice(0, 19), ledgerBefore); await run(migrations);
    assert.deepEqual((await pool.query('select * from schema_migrations order by filename')).rows, ledgerAfter);
    for (const table of ['combined_demo_v4_feedback_responses', 'combined_demo_v4_feedback_comments']) {
      assert.equal((await pool.query(`select count(*) from ${table}`)).rows[0].count, '0');
      for (const operation of ['select', 'insert', 'update', 'delete']) assert.equal((await pool.query('select has_table_privilege(\'public\',$1,$2) as allowed', [table, operation])).rows[0].allowed, false);
    }
    assert.deepEqual((await service.report({ survey_version: version })).totals, { all: 6, current: 0, combined_demo_v4: 0, combined_demo_v3: 3, free_text_v1: 1, multiple_choice_v2: 1, package_v1: 1 });
  });

  const app = express(); app.use(express.json());
  app.use('/v1/demo-feedback', createDemoFeedbackPublicRouter({ service, allowedOrigins: 'http://localhost:4318' }));
  app.use('/admin/api/demo-feedback', (_req, _res, next) => next(), createDemoFeedbackAdminRouter({ service }));
  const bridgeSecret = 'local-v4-read-credential-only-123456789';
  app.use('/internal/feedback-read', createFeedbackReadBridgeRouter({ secret: bridgeSecret, flight: service, packages }));
  server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = body => fetch(base + '/v1/demo-feedback', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:4318' }, body: JSON.stringify(body) });
  const submitted = [];

  await t.test('blank/omitted comments create no comment rows; nonblank text is separately tied to its response', async () => {
    for (const extra of [{}, { optional_comment: '' }, { optional_comment: ' \n\t ' }, { optional_comment: '  Useful feature.\nPlease include baggage.  ', use_likelihood: 'Probably' }, { optional_comment: '=SUM(1,2)\n"quoted" <script>alert(1)</script>', use_likelihood: 'Probably not', booked_travel_last_12_months: false, source: 'friends' }]) {
      clock += 16 * 60 * 1000; const payload = answer(extra); submitted.push(payload);
      assert.equal((await post(payload)).status, 201);
      const row = (await pool.query('select r.*,c.comment from combined_demo_v4_feedback_responses r left join combined_demo_v4_feedback_comments c on c.response_id=r.id where request_id=$1', [payload.request_id])).rows[0];
      for (const key of ['clarity', 'use_likelihood', 'booked_travel_last_12_months', 'source', 'survey_version', 'request_id']) assert.equal(row[key], payload[key]);
      assert.equal(row.comment, payload.optional_comment?.trim() || null);
      for (const key of ['id', 'submitted_at', 'created_at', 'updated_at']) assert.ok(row[key]);
    }
    assert.equal((await pool.query('select count(*) from combined_demo_v4_feedback_comments')).rows[0].count, '2');
  });

  await t.test('idempotency covers comment and structured answers without rewriting either record', async () => {
    const payload = submitted[3]; clock += 16 * 60 * 1000;
    const beforeRetry = (await pool.query('select to_jsonb(r) as response,to_jsonb(c) as comment from combined_demo_v4_feedback_responses r join combined_demo_v4_feedback_comments c on c.response_id=r.id where request_id=$1', [payload.request_id])).rows;
    assert.equal((await post({ ...payload, request_id: payload.request_id.toUpperCase(), optional_comment: payload.optional_comment.trim() })).status, 201);
    for (const change of [{ optional_comment: 'Changed' }, { optional_comment: undefined }, { clarity: 'Somewhat clear' }, { source: 'direct' }]) assert.equal((await post({ ...payload, ...change })).status, 409);
    assert.equal((await post({ ...submitted[0], optional_comment: 'Added after submit' })).status, 409);
    assert.deepEqual((await pool.query('select to_jsonb(r) as response,to_jsonb(c) as comment from combined_demo_v4_feedback_responses r join combined_demo_v4_feedback_comments c on c.response_id=r.id where request_id=$1', [payload.request_id])).rows, beforeRetry);
    clock += 16 * 60 * 1000;
    const concurrent = answer({ optional_comment: 'One comment despite retries.' }); submitted.push(concurrent);
    assert.deepEqual((await Promise.all(Array.from({ length: 4 }, () => post(concurrent)))).map(res => res.status), [201, 201, 201, 201]);
    assert.equal((await pool.query('select count(*) from combined_demo_v4_feedback_responses where request_id=$1', [concurrent.request_id])).rows[0].count, '1');
    assert.equal((await pool.query('select count(*) from combined_demo_v4_feedback_comments c join combined_demo_v4_feedback_responses r on r.id=c.response_id where r.request_id=$1', [concurrent.request_id])).rows[0].count, '1');
  });

  await t.test('a comment write failure rolls back the structured response too', async () => {
    await pool.query("create function fail_test_comment() returns trigger language plpgsql as $$ begin raise exception 'local test write failure'; end $$; create trigger fail_test_comment before insert on combined_demo_v4_feedback_comments for each row execute function fail_test_comment()");
    const payload = answer({ optional_comment: 'Must be atomic.' }); clock += 16 * 60 * 1000;
    assert.equal((await post(payload)).status, 503);
    assert.equal((await pool.query('select count(*) from combined_demo_v4_feedback_responses where request_id=$1', [payload.request_id])).rows[0].count, '0');
    await pool.query('drop trigger fail_test_comment on combined_demo_v4_feedback_comments; drop function fail_test_comment()');
    await assert.rejects(pool.query('insert into combined_demo_v4_feedback_comments(response_id,comment) values($1,$2)', [crypto.randomUUID(), 'Orphan']), error => error.code === '23503');
  });

  await t.test('report keeps v3 meanings, current totals, comments, filters and same-respondent denominator separate', async () => {
    const current = await service.report({ survey_version: version });
    assert.equal(current.surveyVersion, version); assert.deepEqual(current.questions, QUESTIONS);
    assert.equal(current.overall.total, 6); assert.deepEqual(current.overall.validation, { count: 5, percent: 83.3, denominator: 6 });
    assert.equal(current.totals.current, 6); assert.equal(current.totals.combined_demo_v3, 3); assert.equal(current.totals.all, 12);
    assert.equal(current.commentCount, 3); assert.equal(current.comments.length, 3);
    for (const comment of current.comments) { const row = current.rows.find(row => row.id === comment.response_id); assert.equal(comment.comment, row.optional_comment); assert.equal(comment.source, row.source); assert.deepEqual(comment.submitted_at, row.submitted_at); }
    for (const filter of [{ source: 'friends' }, { likelihood: 'Probably not' }, { booked: 'no' }]) {
      const report = await service.report({ survey_version: version, ...filter }); assert.equal(report.overall.total, 1); assert.deepEqual(report.overall.validation, { count: 0, percent: 0, denominator: 1 }); assert.equal(report.commentCount, 1); assert.equal(report.comments[0].source, 'friends');
    }
    const positive = await service.report({ survey_version: version, likelihood: 'Probably', clarity: 'Very clear', booked: 'yes' }); assert.equal(positive.overall.total, 1); assert.equal(positive.overall.validation.percent, 100);
    const empty = await service.report({ survey_version: version, from: '2000-01-01', to: '2000-01-01' }); assert.deepEqual(empty.overall.validation, { count: 0, percent: null, denominator: 0 }); assert.equal(empty.commentCount, 0); assert.deepEqual(empty.comments, []);
    const dated = await service.report({ survey_version: version, from: new Date().toISOString().slice(0, 10), to: new Date().toISOString().slice(0, 10) }); assert.equal(dated.overall.total, 6);
    const previous = await service.report({ survey_version: 'combined_demo_v3' }); assert.equal(previous.overall.total, 3); assert.deepEqual(previous.questions, V3_QUESTIONS); assert.equal(previous.totals.current, 6); assert.equal(previous.comments, undefined); assert.ok(previous.rows.every(row => !Object.hasOwn(row, 'optional_comment')));
    for (const survey_version of ['free_text_v1', 'multiple_choice_v2']) { const report = await service.report({ survey_version }); assert.equal(report.overall.total, 1); assert.equal(report.totals.current, 6); assert.equal(report.totals.combined_demo_v3, 3); }
  });

  await t.test('CSV appends optional comments, escapes formulas/multiline text and preserves all prior CSV bytes', async () => {
    const text = await csv(service, { survey_version: version });
    assert.ok(text.startsWith('\uFEFF"Response ID"'));
    assert.ok(text.split('\r\n')[0].endsWith('"Booked travel in last 12 months","Optional comment"'));
    assert.equal(text.split('\r\n')[0].split(',').length, 21);
    assert.ok(text.includes('"\'=SUM(1,2)\n""quoted"" <script>alert(1)</script>"'));
    const friends = await csv(service, { survey_version: version, source: 'friends' }); assert.ok(friends.includes('SUM(1,2)')); assert.ok(!friends.includes('Useful feature.'));
    assert.deepEqual(await protectedExports(), exportsBefore); assert.deepEqual(await snapshot(), before);
  });

  await t.test('HTTP reports/exports remain private and public validation/rate limiting continue', async () => {
    for (const suffix of ['', '/export.csv']) assert.equal((await fetch(base + '/admin/api/demo-feedback' + suffix + '?survey_version=' + version)).status, 401);
    const headers = { 'x-zippi-feedback-read': bridgeSecret };
    const read = await fetch(base + '/internal/feedback-read/demo-feedback?survey_version=' + version, { headers }); assert.equal(read.status, 200); assert.equal((await read.json()).commentCount, 3);
    const exported = await fetch(base + '/internal/feedback-read/demo-feedback/export.csv?survey_version=' + version, { headers }); assert.equal(exported.status, 200); assert.ok((await exported.text()).includes('Optional comment'));
    clock += 16 * 60 * 1000;
    for (const optional_comment of [null, {}, 'a'.repeat(2001), 'bad\u0001']) assert.equal((await post(answer({ optional_comment }))).status, 400);
    clock += 16 * 60 * 1000;
    for (let i = 0; i < 10; i++) assert.equal((await post({ survey_version: i % 2 ? version : 'combined_demo_v3' })).status, 400);
    assert.equal((await post(answer())).status, 429);
    assert.deepEqual(await snapshot(), before); assert.deepEqual(await protectedExports(), exportsBefore);
  });

  await t.test('comments align to response pages while comment count and CSV cover every matching response', async () => {
    for (let i = 0; i < 48; i++) { clock += 16 * 60 * 1000; await service.submit(answer({ optional_comment: i % 2 ? '' : `Page comment ${i}` }), 'pagination'); }
    const first = await service.report({ survey_version: version, sort: 'oldest' });
    const second = await service.report({ survey_version: version, sort: 'oldest', page: '2' });
    assert.equal(first.rows.length, 50); assert.equal(second.rows.length, 4); assert.equal(second.pages, 2);
    assert.equal(first.commentCount, 27); assert.equal(second.commentCount, 27);
    assert.equal(first.comments.length + second.comments.length, 27);
    for (const report of [first, second]) assert.ok(report.comments.every(comment => report.rows.some(row => row.id === comment.response_id)));
    const exported = await csv(service, { survey_version: version, page: '2' });
    for (const row of [...first.rows, ...second.rows]) assert.ok(exported.includes(row.id));
    for (const payload of originalV3) { clock += 16 * 60 * 1000; await service.submit(payload, 'v3-retry'); }
    assert.deepEqual(await snapshot(), before); assert.deepEqual(await protectedExports(), exportsBefore);
  });
});
