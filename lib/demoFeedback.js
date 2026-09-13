const crypto = require('node:crypto');

const LIKELIHOODS = Object.freeze(['Definitely', 'Probably', 'Probably not', 'Definitely not']);
const COMPREHENSION_CHOICES = Object.freeze([
  ['natural_language_flight_search', 'Lets you search for flights by describing what you want in normal language'],
  ['deals_and_price_alerts', 'Compares travel deals and sends price alerts'],
  ['automatic_trip_booking', 'Books complete trips automatically for you'],
  ['general_travel_chatbot', 'Acts as a travel chatbot for general questions'],
  ['not_sure', 'I’m not really sure'],
].map(([value,label]) => Object.freeze({value,label})));
const PAGE_SIZE = 50;
const WINDOW_MS = 15 * 60 * 1000;
const FIELDS = 'id, comprehension_choice, understanding as own_words, likelihood, reason as additional_comments, recent_flight_shopper, source, submitted_at, created_at, updated_at';
class FeedbackError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
function text(value) {
  if (typeof value !== 'string' || value.length > 2000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) throw new FeedbackError(400, 'invalid_text');
  const clean = value.trim();
  return clean;
}
function validateSubmission(body) {
  if (!body || Array.isArray(body) || typeof body !== 'object') throw new FeedbackError(400, 'invalid_submission');
  if (body.website !== undefined && body.website !== '') throw new FeedbackError(400, 'invalid_submission');
  if (typeof body.request_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.request_id)) throw new FeedbackError(400, 'invalid_request_id');
  if (!COMPREHENSION_CHOICES.some(choice => choice.value === body.comprehension_choice)) throw new FeedbackError(400, 'invalid_comprehension_choice');
  if (!LIKELIHOODS.includes(body.likelihood)) throw new FeedbackError(400, 'invalid_likelihood');
  if (typeof body.recent_flight_shopper !== 'boolean') throw new FeedbackError(400, 'invalid_recent_flight_shopper');
  const source = body.source === undefined || body.source === '' ? 'direct' : body.source;
  if (typeof source !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(source)) throw new FeedbackError(400, 'invalid_source');
  return { request_id: body.request_id, comprehension_choice: body.comprehension_choice, own_words: text(body.own_words ?? ''), likelihood: body.likelihood,
    additional_comments: text(body.additional_comments ?? ''), recent_flight_shopper: body.recent_flight_shopper, source };
}
function parseFilters(query = {}) {
  const out = { sort: 'newest', page: 1 };
  for (const key of ['source', 'likelihood', 'recent', 'from', 'to', 'sort', 'page']) {
    const value = query[key];
    if (value === undefined || value === '') continue;
    if (typeof value !== 'string') throw new FeedbackError(400, 'invalid_filter');
    out[key] = value;
  }
  if (out.source && !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(out.source)) throw new FeedbackError(400, 'invalid_source');
  if (out.likelihood && !LIKELIHOODS.includes(out.likelihood)) throw new FeedbackError(400, 'invalid_likelihood');
  if (out.recent && !['yes', 'no'].includes(out.recent)) throw new FeedbackError(400, 'invalid_recent_filter');
  for (const key of ['from', 'to']) {
    if (out[key] && (!/^\d{4}-\d{2}-\d{2}$/.test(out[key]) || !Number.isFinite(Date.parse(out[key])) || new Date(out[key]).toISOString().slice(0, 10) !== out[key] || out[key] < '2000-01-01' || out[key] > '2099-12-31')) throw new FeedbackError(400, 'invalid_date');
  }
  if (out.from && out.to && out.from > out.to) throw new FeedbackError(400, 'invalid_date_range');
  if (!['newest', 'oldest'].includes(out.sort)) throw new FeedbackError(400, 'invalid_sort');
  if (!/^[1-9]\d{0,6}$/.test(String(out.page))) throw new FeedbackError(400, 'invalid_page');
  out.page = Number(out.page);
  return out;
}
function filterSql(filters) {
  const clauses = []; const params = [];
  const add = (sql, value) => { params.push(value); clauses.push(sql.replace('?', `$${params.length}`)); };
  if (filters.source) add('source = ?', filters.source);
  if (filters.likelihood) add('likelihood = ?', filters.likelihood);
  if (filters.recent) add('recent_flight_shopper = ?', filters.recent === 'yes');
  if (filters.from) add('submitted_at >= ?::timestamptz', `${filters.from}T00:00:00Z`);
  if (filters.to) add('submitted_at < ?::timestamptz', new Date(Date.parse(filters.to) + 86400000).toISOString());
  return { where: clauses.length ? `where ${clauses.join(' and ')}` : '', params };
}
function summarize(groups) {
  const make = () => ({ total: 0, likelihoods: Object.fromEntries(LIKELIHOODS.map(x => [x, { count: 0, percent: 0 }])), positive: { count: 0, percent: 0 }, recent: { count: 0, percent: 0 },
    comprehension: { answered:0, notAsked:0, correct:{count:0,percent:null}, choices:Object.fromEntries(COMPREHENSION_CHOICES.map(choice => [choice.value, {...choice,count:0,percent:null}])) } });
  const overall = make(); const shoppers = make(); const sources = new Map();
  function add(summary, row) {
    const count = Number(row.count); summary.total += count; summary.likelihoods[row.likelihood].count += count;
    if (row.recent_flight_shopper) summary.recent.count += count;
    if (row.comprehension_choice) {
      summary.comprehension.answered += count;
      summary.comprehension.choices[row.comprehension_choice].count += count;
    } else summary.comprehension.notAsked += count;
    if (['Definitely', 'Probably'].includes(row.likelihood)) summary.positive.count += count;
  }
  for (const row of groups) {
    add(overall, row); if (row.recent_flight_shopper) add(shoppers, row);
    if (!sources.has(row.source)) sources.set(row.source, make());
    add(sources.get(row.source), row);
  }
  function finish(summary) {
    for (const value of [...Object.values(summary.likelihoods), summary.positive, summary.recent]) value.percent = summary.total ? Math.round(value.count / summary.total * 1000) / 10 : 0;
    const comprehension=summary.comprehension;
    for (const choice of Object.values(comprehension.choices)) choice.percent = comprehension.answered ? Math.round(choice.count / comprehension.answered * 1000) / 10 : null;
    const correct=comprehension.choices.natural_language_flight_search;
    comprehension.correct={count:correct.count,percent:correct.percent};
    return summary;
  }
  return { overall: finish(overall), shoppers: finish(shoppers), sources: [...sources].map(([source, summary]) => ({ source, ...finish(summary) })) };
}
// Quote every cell and neutralize spreadsheet formula prefixes, including leading whitespace.
function csvCell(value) {
  let str = value instanceof Date ? value.toISOString() : String(value ?? '');
  if (/^\s*[=+@-]/.test(str) || /^[\t\r\n]/.test(str)) str = `'${str}`;
  return `"${str.replace(/"/g, '""')}"`;
}
const CSV_HEADERS = ['Response ID', 'Comprehension choice', 'Comprehension description', 'Own-words description', 'Likelihood to use', 'Recent flight shopper', 'Additional comments', 'Source', 'Submitted at (UTC)', 'Created at (UTC)', 'Updated at (UTC)', 'Question format'];
function csvLine(row) {
  const label=COMPREHENSION_CHOICES.find(choice => choice.value === row.comprehension_choice)?.label || 'Not asked (earlier form)';
  return [row.id, row.comprehension_choice, label, row.own_words, row.likelihood, row.recent_flight_shopper ? 'Yes' : 'No', row.additional_comments, row.source, row.submitted_at, row.created_at, row.updated_at, row.comprehension_choice ? 'multiple_choice_v2' : 'free_text_v1'].map(csvCell).join(',') + '\r\n';
}

function createDemoFeedbackService({ dbPool, secret, now = Date.now }) {
  function ready() { if (!dbPool || !secret) throw new FeedbackError(503, 'feedback_unavailable'); }
  async function rateLimit(ip) {
    const stamp = now(); const window = Math.floor(stamp / WINDOW_MS);
    const key = crypto.createHmac('sha256', secret).update(`demo-feedback:${window}:${ip || 'unknown'}`).digest('hex');
    const expires = new Date((window + 1) * WINDOW_MS);
    const row = (await dbPool.query(`insert into demo_feedback_rate_limits(bucket_key,count,expires_at) values($1,1,$2)
      on conflict(bucket_key) do update set count=least(demo_feedback_rate_limits.count+1,100) returning count`, [key, expires])).rows[0];
    await dbPool.query('delete from demo_feedback_rate_limits where expires_at <= $1', [new Date(stamp)]);
    if (row.count > 10) throw new FeedbackError(429, 'rate_limited');
  }
  async function submit(body, ip) {
    ready(); await rateLimit(ip); const data = validateSubmission(body);
    const values = [crypto.randomUUID(), data.request_id, data.own_words, data.likelihood, data.additional_comments, data.recent_flight_shopper, data.source, data.comprehension_choice];
    const inserted = (await dbPool.query(`insert into demo_feedback_responses(id,request_id,understanding,likelihood,reason,recent_flight_shopper,source,comprehension_choice)
      values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(request_id) do nothing returning id`, values)).rows[0];
    if (inserted) return { ok: true };
    // Retries acknowledge only the exact same payload; no response content is returned.
    const existing = (await dbPool.query('select comprehension_choice,understanding as own_words,likelihood,reason as additional_comments,recent_flight_shopper,source from demo_feedback_responses where request_id=$1', [data.request_id])).rows[0];
    if (!existing || Object.keys(existing).some(key => existing[key] !== data[key])) throw new FeedbackError(409, 'submission_conflict');
    return { ok: true };
  }
  async function report(query) {
    ready(); const filters = parseFilters(query); const { where, params } = filterSql(filters);
    const client = await dbPool.connect();
    try {
      await client.query('begin isolation level repeatable read read only');
      const groups = (await client.query(`select source,likelihood,recent_flight_shopper,comprehension_choice,count(*)::int as count from demo_feedback_responses ${where} group by source,likelihood,recent_flight_shopper,comprehension_choice order by source`, params)).rows;
      const summary = summarize(groups);
      const pages = Math.max(1, Math.ceil(summary.overall.total / PAGE_SIZE)); filters.page = Math.min(filters.page, pages);
      const dir = filters.sort === 'oldest' ? 'asc' : 'desc';
      const rows = (await client.query(`select ${FIELDS} from demo_feedback_responses ${where} order by submitted_at ${dir},id ${dir} limit ${PAGE_SIZE} offset $${params.length + 1}`, [...params, (filters.page - 1) * PAGE_SIZE])).rows;
      const sources = (await client.query('select distinct source from demo_feedback_responses order by source')).rows.map(row => row.source);
      await client.query('commit');
      return { ok: true, ...summary, rows, sourceOptions: sources, page: filters.page, pages, pageSize: PAGE_SIZE };
    } catch (error) { await client.query('rollback'); throw error; } finally { client.release(); }
  }
  async function* exportCsv(query) {
    ready(); const filters = parseFilters(query); const { where, params } = filterSql(filters);
    const client = await dbPool.connect(); let complete = false;
    try {
      await client.query('begin isolation level repeatable read read only');
      const dir = filters.sort === 'oldest' ? 'asc' : 'desc';
      await client.query(`declare feedback_export no scroll cursor for select ${FIELDS} from demo_feedback_responses ${where} order by submitted_at ${dir},id ${dir}`, params);
      yield '\uFEFF' + CSV_HEADERS.map(csvCell).join(',') + '\r\n';
      while (true) {
        const { rows } = await client.query('fetch forward 500 from feedback_export');
        if (!rows.length) break;
        yield rows.map(csvLine).join('');
      }
      await client.query('commit'); complete = true;
    } finally { try { if (!complete) await client.query('rollback'); } finally { client.release(); } }
  }
  return { submit, report, exportCsv };
}
module.exports = { createDemoFeedbackService, FeedbackError, LIKELIHOODS, COMPREHENSION_CHOICES, validateSubmission, parseFilters, filterSql, summarize, csvCell, csvLine };
