const crypto = require('node:crypto');
const { FeedbackError, LIKELIHOODS, csvCell } = require('./demoFeedback');
const SURVEY_VERSION = 'combined_demo_v3';
const CLARITY = Object.freeze(['Very clear', 'Somewhat clear', 'Not very clear', 'Not clear at all']);
const QUESTIONS = Object.freeze([
  { id: 'clarity', text: 'How clear is it what Zippi does?', options: CLARITY },
  { id: 'use_likelihood', text: 'Based on what you saw, how likely would you be to use Zippi when planning your next trip?', options: LIKELIHOODS },
  { id: 'booked_travel_last_12_months', text: 'Have you personally booked a flight, hotel, or vacation package in the last 12 months?', options: ['Yes', 'No'] },
]);
const FIELDS = 'id,request_id,survey_version,clarity,use_likelihood,booked_travel_last_12_months,source,submitted_at,created_at,updated_at';
const EXTRA_HEADERS = ['Survey version', 'Request ID', 'Clarity question ID', 'Clarity', 'Use likelihood question ID', 'Use likelihood', 'Booking question ID', 'Booked travel in last 12 months'];
function invalid(code) { throw new FeedbackError(400, code); }
function validateCombinedSubmission(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || (body.website !== undefined && body.website !== '')) invalid('invalid_submission');
  if (body.survey_version !== SURVEY_VERSION) invalid('invalid_survey_version');
  if (typeof body.request_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.request_id)) invalid('invalid_request_id');
  if (!CLARITY.includes(body.clarity)) invalid('invalid_clarity');
  if (!LIKELIHOODS.includes(body.use_likelihood)) invalid('invalid_use_likelihood');
  if (typeof body.booked_travel_last_12_months !== 'boolean') invalid('invalid_booked_travel');
  const source = body.source === undefined || body.source === '' ? 'direct' : body.source;
  if (typeof source !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(source)) invalid('invalid_source');
  return { request_id: body.request_id.toLowerCase(), survey_version: SURVEY_VERSION, clarity: body.clarity, use_likelihood: body.use_likelihood, booked_travel_last_12_months: body.booked_travel_last_12_months, source };
}
function combinedFilterSql(filters, { totals = false } = {}) {
  const clauses = []; const params = [];
  const add = (sql, value) => { params.push(value); clauses.push(sql.replace('?', `$${params.length}`)); };
  if (filters.source) add('source = ?', filters.source);
  if (!totals) {
    if (filters.likelihood) add('use_likelihood = ?', filters.likelihood);
    if (filters.clarity) add('clarity = ?', filters.clarity);
    if (filters.booked) add('booked_travel_last_12_months = ?', filters.booked === 'yes');
  }
  if (filters.from) add('submitted_at >= ?::timestamptz', `${filters.from}T00:00:00Z`);
  if (filters.to) add('submitted_at < ?::timestamptz', new Date(Date.parse(filters.to) + 86400000).toISOString());
  return { where: clauses.length ? `where ${clauses.join(' and ')}` : '', params };
}
const percent = (count, total) => total ? Math.round(count / total * 1000) / 10 : null;
function summarizeCombined(groups) {
  const make = () => ({ total: 0, clarity: Object.fromEntries(CLARITY.map(x => [x, { count: 0, percent: null }])), likelihoods: Object.fromEntries(LIKELIHOODS.map(x => [x, { count: 0, percent: null }])), positive: { count: 0, percent: null }, booked: { answered: 0, yes: { count: 0, percent: null }, no: { count: 0, percent: null } }, validation: { count: 0, percent: null, denominator: 0 } });
  const overall = make(); const sources = new Map();
  function add(summary, row) {
    const count = Number(row.count); summary.total += count;
    summary.clarity[row.clarity].count += count; summary.likelihoods[row.use_likelihood].count += count;
    const positive = ['Definitely', 'Probably'].includes(row.use_likelihood);
    if (positive) summary.positive.count += count;
    if (typeof row.booked_travel_last_12_months === 'boolean') {
      summary.booked.answered += count;
      summary.booked[row.booked_travel_last_12_months ? 'yes' : 'no'].count += count;
      if (row.booked_travel_last_12_months && positive) summary.validation.count += count;
    }
  }
  for (const row of groups) {
    add(overall, row);
    if (!sources.has(row.source)) sources.set(row.source, make());
    add(sources.get(row.source), row);
  }
  function finish(summary) {
    for (const value of [...Object.values(summary.clarity), ...Object.values(summary.likelihoods), summary.positive]) value.percent = percent(value.count, summary.total);
    for (const value of [summary.booked.yes, summary.booked.no]) value.percent = percent(value.count, summary.booked.answered);
    summary.validation.denominator = summary.booked.answered;
    summary.validation.percent = percent(summary.validation.count, summary.validation.denominator);
    return summary;
  }
  return { overall: finish(overall), sources: [...sources].map(([source, summary]) => ({ source, ...finish(summary) })) };
}
async function surveyTotals(client, filters) {
  const { where, params } = combinedFilterSql(filters, { totals: true });
  const current = Number((await client.query(`select count(*) from combined_demo_feedback_responses ${where}`, params)).rows[0].count);
  const history = (await client.query(`select comprehension_choice is null as free_text,count(*)::int as count from demo_feedback_responses ${where} group by comprehension_choice is null`, params)).rows;
  const package_v1 = Number((await client.query(`select count(*) from package_feedback_responses ${where}`, params)).rows[0].count);
  const free_text_v1 = Number(history.find(row => row.free_text)?.count || 0);
  const multiple_choice_v2 = Number(history.find(row => !row.free_text)?.count || 0);
  return { all: current + free_text_v1 + multiple_choice_v2 + package_v1, current, free_text_v1, multiple_choice_v2, package_v1 };
}
function combinedCsvLine(row) {
  // Original question columns are blank: these answers have different meanings.
  return [row.id, '', '', '', '', '', '', row.source, row.submitted_at, row.created_at, row.updated_at, SURVEY_VERSION,
    row.survey_version, row.request_id, 'clarity', row.clarity, 'use_likelihood', row.use_likelihood, 'booked_travel_last_12_months', row.booked_travel_last_12_months ? 'Yes' : 'No'].map(csvCell).join(',') + '\r\n';
}
function createCombinedDemoFeedbackService({ dbPool, parseFilters, csvHeaders }) {
  async function submit(body) {
    const data = validateCombinedSubmission(body);
    const columns = Object.keys(data);
    const row = (await dbPool.query(`insert into combined_demo_feedback_responses(id,${columns.join(',')}) values($1,${columns.map((_, i) => `$${i + 2}`).join(',')}) on conflict(request_id) do nothing returning id`, [crypto.randomUUID(), ...Object.values(data)])).rows[0];
    if (!row) {
      const existing = (await dbPool.query(`select ${columns.join(',')} from combined_demo_feedback_responses where request_id=$1`, [data.request_id])).rows[0];
      if (!existing || columns.some(key => existing[key] !== data[key])) throw new FeedbackError(409, 'submission_conflict');
    }
    return { ok: true };
  }
  async function report(query) {
    const filters = parseFilters(query); const { where, params } = combinedFilterSql(filters);
    const client = await dbPool.connect();
    try {
      await client.query('begin isolation level repeatable read read only');
      const groups = (await client.query(`select source,clarity,use_likelihood,booked_travel_last_12_months,count(*)::int as count from combined_demo_feedback_responses ${where} group by source,clarity,use_likelihood,booked_travel_last_12_months order by source`, params)).rows;
      const summary = summarizeCombined(groups); const pages = Math.max(1, Math.ceil(summary.overall.total / 50)); const page = Math.min(filters.page, pages);
      const dir = filters.sort === 'oldest' ? 'asc' : 'desc';
      const rows = (await client.query(`select ${FIELDS} from combined_demo_feedback_responses ${where} order by submitted_at ${dir},id ${dir} limit 50 offset $${params.length + 1}`, [...params, (page - 1) * 50])).rows;
      const sourceOptions = (await client.query('select source from combined_demo_feedback_responses union select source from demo_feedback_responses union select source from package_feedback_responses order by source')).rows.map(row => row.source);
      const totals = await surveyTotals(client, filters);
      await client.query('commit');
      return { ok: true, surveyVersion: SURVEY_VERSION, questions: QUESTIONS, ...summary, totals, rows, sourceOptions, page, pages, pageSize: 50 };
    } catch (error) { await client.query('rollback'); throw error; } finally { client.release(); }
  }
  async function* exportCsv(query) {
    const filters = parseFilters(query); const { where, params } = combinedFilterSql(filters); const client = await dbPool.connect(); let complete = false;
    try {
      await client.query('begin isolation level repeatable read read only');
      const dir = filters.sort === 'oldest' ? 'asc' : 'desc';
      await client.query(`declare combined_feedback_export no scroll cursor for select ${FIELDS} from combined_demo_feedback_responses ${where} order by submitted_at ${dir},id ${dir}`, params);
      yield '\uFEFF' + [...csvHeaders, ...EXTRA_HEADERS].map(csvCell).join(',') + '\r\n';
      while (true) { const { rows } = await client.query('fetch forward 500 from combined_feedback_export'); if (!rows.length) break; yield rows.map(combinedCsvLine).join(''); }
      await client.query('commit'); complete = true;
    } finally { try { if (!complete) await client.query('rollback'); } finally { client.release(); } }
  }
  return { submit, report, exportCsv };
}
module.exports = { SURVEY_VERSION, CLARITY, QUESTIONS, EXTRA_HEADERS, validateCombinedSubmission, combinedFilterSql, summarizeCombined, surveyTotals, combinedCsvLine, createCombinedDemoFeedbackService };
