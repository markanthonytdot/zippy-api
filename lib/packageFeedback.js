const crypto = require('node:crypto');
const { FeedbackError, LIKELIHOODS, parseFilters: parseCommonFilters, csvCell } = require('./demoFeedback');

const USEFULNESS = Object.freeze(['Yes', 'No', 'Not sure']);
const ENTRY_PATHS = Object.freeze(['direct', 'flight_thank_you']);
const PAGE_SIZE = 50;
const WINDOW_MS = 15 * 60 * 1000;
const FIELDS = 'id,demo_type,likelihood,usefulness,comment,source,entry_path,submitted_at,created_at,updated_at';
const CSV_HEADERS = ['Response ID', 'Demo type', 'Submitted at (UTC)', 'Source', 'Entry path', 'Likelihood to use', 'More useful than separate search', 'Additional comments'];

function invalid(code) { throw new FeedbackError(400, code); }
function uuid(value, code) {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) invalid(code);
  return value;
}
function sourceValue(value) {
  if (value === undefined || value === '') return 'direct';
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)) invalid('invalid_source');
  return value;
}
function bodyObject(body) {
  if (!body || Array.isArray(body) || typeof body !== 'object' || (body.website !== undefined && body.website !== '')) invalid('invalid_submission');
}
function validatePackageSubmission(body) {
  bodyObject(body);
  const request_id = uuid(body.request_id, 'invalid_request_id');
  if (body.demo_type !== undefined && body.demo_type !== 'package') invalid('invalid_demo_type');
  if (!LIKELIHOODS.includes(body.likelihood)) invalid('invalid_likelihood');
  if (!USEFULNESS.includes(body.usefulness)) invalid('invalid_usefulness');
  const entry_path = body.entry_path === undefined ? 'direct' : body.entry_path;
  if (!ENTRY_PATHS.includes(entry_path)) invalid('invalid_entry_path');
  const comment = body.comment ?? '';
  if (typeof comment !== 'string' || comment.length > 2000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(comment)) invalid('invalid_comment');
  return { request_id, demo_type: 'package', likelihood: body.likelihood, usefulness: body.usefulness, comment: comment.trim(), source: sourceValue(body.source), entry_path };
}
function validatePackageClick(body) {
  bodyObject(body);
  if (body.entry_path !== 'flight_thank_you') invalid('invalid_entry_path');
  return { event_id: uuid(body.event_id, 'invalid_event_id'), source: sourceValue(body.source) };
}
function parsePackageFilters(query = {}) {
  const common = Object.fromEntries(['source', 'likelihood', 'from', 'to', 'sort', 'page'].map(key => [key, query[key]]));
  const filters = parseCommonFilters(common);
  for (const [key, allowed] of [['usefulness', USEFULNESS], ['entry_path', ENTRY_PATHS]]) {
    if (query[key] === undefined || query[key] === '') continue;
    if (!allowed.includes(query[key])) invalid(`invalid_${key}`);
    filters[key] = query[key];
  }
  return filters;
}
function packageFilterSql(filters, { funnel = false, timeColumn = 'submitted_at' } = {}) {
  const clauses = []; const params = [];
  const add = (sql, value) => { params.push(value); clauses.push(sql.replace('?', `$${params.length}`)); };
  if (filters.source) add('source = ?', filters.source);
  if (!funnel) for (const key of ['likelihood', 'usefulness', 'entry_path']) if (filters[key]) add(`${key} = ?`, filters[key]);
  if (filters.from) add(`${timeColumn} >= ?::timestamptz`, `${filters.from}T00:00:00Z`);
  if (filters.to) add(`${timeColumn} < ?::timestamptz`, new Date(Date.parse(filters.to) + 86400000).toISOString());
  return { where: clauses.length ? `where ${clauses.join(' and ')}` : '', params };
}
const percent = (count, total) => total ? Math.round(count / total * 1000) / 10 : 0;
function summarizePackages(groups) {
  const make = () => ({ total: 0, likelihoods: Object.fromEntries(LIKELIHOODS.map(x => [x, { count: 0, percent: 0 }])), usefulness: Object.fromEntries(USEFULNESS.map(x => [x, { count: 0, percent: 0 }])), entryPaths: Object.fromEntries(ENTRY_PATHS.map(x => [x, { count: 0, percent: 0 }])), positive: { count: 0, percent: 0 } });
  const overall = make(); const sources = new Map();
  const add = (summary, row) => {
    const count = Number(row.count); summary.total += count;
    summary.likelihoods[row.likelihood].count += count;
    summary.usefulness[row.usefulness].count += count;
    summary.entryPaths[row.entry_path].count += count;
    if (['Definitely', 'Probably'].includes(row.likelihood)) summary.positive.count += count;
  };
  for (const row of groups) {
    add(overall, row);
    if (!sources.has(row.source)) sources.set(row.source, make());
    add(sources.get(row.source), row);
  }
  const finish = summary => {
    for (const value of [...Object.values(summary.likelihoods), ...Object.values(summary.usefulness), ...Object.values(summary.entryPaths), summary.positive]) value.percent = percent(value.count, summary.total);
    return summary;
  };
  return { overall: finish(overall), sources: [...sources].map(([source, summary]) => ({ source, ...finish(summary) })) };
}
function packageFunnel(flightCompleted, packageClicks, fromFlightSubmitted) {
  return { flightCompleted, packageClicks, fromFlightSubmitted, clickThroughPercent: flightCompleted ? percent(packageClicks, flightCompleted) : null, completionAfterClickPercent: packageClicks ? percent(fromFlightSubmitted, packageClicks) : null };
}
function packageCsvLine(row) {
  return [row.id, row.demo_type, row.submitted_at, row.source, row.entry_path, row.likelihood, row.usefulness, row.comment].map(csvCell).join(',') + '\r\n';
}
function createPackageFeedbackService({ dbPool, secret, now = Date.now }) {
  const ready = () => { if (!dbPool || !secret) throw new FeedbackError(503, 'feedback_unavailable'); };
  async function rateLimit(kind, ip) {
    const stamp = now(); const window = Math.floor(stamp / WINDOW_MS);
    const key = crypto.createHmac('sha256', secret).update(`package-feedback:${kind}:${window}:${ip || 'unknown'}`).digest('hex');
    const row = (await dbPool.query(`insert into package_feedback_rate_limits(bucket_key,count,expires_at) values($1,1,$2)
      on conflict(bucket_key) do update set count=least(package_feedback_rate_limits.count+1,100) returning count`, [key, new Date((window + 1) * WINDOW_MS)])).rows[0];
    await dbPool.query('delete from package_feedback_rate_limits where expires_at <= $1', [new Date(stamp)]);
    if (row.count > 10) throw new FeedbackError(429, 'rate_limited');
  }
  async function submit(body, ip) {
    ready(); await rateLimit('response', ip); const data = validatePackageSubmission(body);
    const inserted = (await dbPool.query(`insert into package_feedback_responses(id,request_id,demo_type,likelihood,usefulness,comment,source,entry_path)
      values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(request_id) do nothing returning id`, [crypto.randomUUID(), data.request_id, data.demo_type, data.likelihood, data.usefulness, data.comment, data.source, data.entry_path])).rows[0];
    if (!inserted) {
      const existing = (await dbPool.query('select demo_type,likelihood,usefulness,comment,source,entry_path from package_feedback_responses where request_id=$1', [data.request_id])).rows[0];
      if (!existing || Object.keys(existing).some(key => existing[key] !== data[key])) throw new FeedbackError(409, 'submission_conflict');
    }
    return { ok: true };
  }
  async function recordClick(body, ip) {
    ready(); await rateLimit('click', ip); const data = validatePackageClick(body);
    const inserted = (await dbPool.query('insert into package_feedback_clicks(event_id,source) values($1,$2) on conflict(event_id) do nothing returning event_id', [data.event_id, data.source])).rows[0];
    if (!inserted) {
      const previous = (await dbPool.query('select source from package_feedback_clicks where event_id=$1', [data.event_id])).rows[0];
      if (!previous || previous.source !== data.source) throw new FeedbackError(409, 'event_conflict');
    }
    return { ok: true };
  }
  async function report(query) {
    ready(); const filters = parsePackageFilters(query); const { where, params } = packageFilterSql(filters);
    const client = await dbPool.connect();
    try {
      await client.query('begin isolation level repeatable read read only');
      const groups = (await client.query(`select source,likelihood,usefulness,entry_path,count(*)::int as count from package_feedback_responses ${where} group by source,likelihood,usefulness,entry_path order by source`, params)).rows;
      const summary = summarizePackages(groups);
      const pages = Math.max(1, Math.ceil(summary.overall.total / PAGE_SIZE)); filters.page = Math.min(filters.page, pages);
      const dir = filters.sort === 'oldest' ? 'asc' : 'desc';
      const rows = (await client.query(`select ${FIELDS} from package_feedback_responses ${where} order by submitted_at ${dir},id ${dir} limit ${PAGE_SIZE} offset $${params.length + 1}`, [...params, (filters.page - 1) * PAGE_SIZE])).rows;
      const responseRange = packageFilterSql(filters, { funnel: true });
      const clickRange = packageFilterSql(filters, { funnel: true, timeColumn: 'created_at' });
      const flightCompleted = Number((await client.query(`select count(*) from demo_feedback_responses ${responseRange.where}`, responseRange.params)).rows[0].count);
      const packageClicks = Number((await client.query(`select count(*) from package_feedback_clicks ${clickRange.where}`, clickRange.params)).rows[0].count);
      const fromFlightSubmitted = Number((await client.query(`select count(*) from package_feedback_responses ${responseRange.where} ${responseRange.where ? 'and' : 'where'} entry_path='flight_thank_you'`, responseRange.params)).rows[0].count);
      const sourceOptions = (await client.query('select source from package_feedback_responses union select source from package_feedback_clicks union select source from demo_feedback_responses order by source')).rows.map(row => row.source);
      await client.query('commit');
      return { ok: true, demoType: 'package', ...summary, funnel: packageFunnel(flightCompleted, packageClicks, fromFlightSubmitted), rows, sourceOptions, page: filters.page, pages, pageSize: PAGE_SIZE };
    } catch (error) { await client.query('rollback'); throw error; } finally { client.release(); }
  }
  async function* exportCsv(query) {
    ready(); const filters = parsePackageFilters(query); const { where, params } = packageFilterSql(filters);
    const client = await dbPool.connect(); let complete = false;
    try {
      await client.query('begin isolation level repeatable read read only');
      const dir = filters.sort === 'oldest' ? 'asc' : 'desc';
      await client.query(`declare package_export no scroll cursor for select ${FIELDS} from package_feedback_responses ${where} order by submitted_at ${dir},id ${dir}`, params);
      yield '\uFEFF' + CSV_HEADERS.map(csvCell).join(',') + '\r\n';
      while (true) {
        const { rows } = await client.query('fetch forward 500 from package_export');
        if (!rows.length) break;
        yield rows.map(packageCsvLine).join('');
      }
      await client.query('commit'); complete = true;
    } finally { try { if (!complete) await client.query('rollback'); } finally { client.release(); } }
  }
  return { submit, recordClick, report, exportCsv };
}
module.exports = { createPackageFeedbackService, validatePackageSubmission, validatePackageClick, parsePackageFilters, packageFilterSql, summarizePackages, packageFunnel, packageCsvLine, USEFULNESS, ENTRY_PATHS, CSV_HEADERS };
