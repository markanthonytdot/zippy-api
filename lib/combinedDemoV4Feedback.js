const crypto = require('node:crypto');
const { FeedbackError, LIKELIHOODS, csvCell } = require('./demoFeedback');
const { CLARITY, QUESTIONS: V3_QUESTIONS, EXTRA_HEADERS, combinedFilterSql, summarizeCombined } = require('./combinedDemoFeedback');

const SURVEY_VERSION = 'combined_demo_v4';
const MAX_COMMENT_LENGTH = 2000;
const QUESTIONS = Object.freeze([
  V3_QUESTIONS[0],
  { id: 'use_likelihood', text: 'If this feature were available on a travel website or app you already use, how likely would you be to use it?', options: LIKELIHOODS },
  V3_QUESTIONS[2],
]);
const OPTIONAL_COMMENT = Object.freeze({ id: 'optional_comment', text: "Anything else you'd like to share?", optional: true, maxLength: MAX_COMMENT_LENGTH });
const FIELDS = 'id,request_id,survey_version,clarity,use_likelihood,booked_travel_last_12_months,source,submitted_at,created_at,updated_at';
const COMMENT_FIELD = "coalesce((select comment from combined_demo_v4_feedback_comments where response_id=r.id),'') as optional_comment";

function invalid(code) { throw new FeedbackError(400, code); }
function validateV4Submission(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || (body.website !== undefined && body.website !== '')) invalid('invalid_submission');
  if (body.survey_version !== SURVEY_VERSION) invalid('invalid_survey_version');
  if (typeof body.request_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.request_id)) invalid('invalid_request_id');
  if (!CLARITY.includes(body.clarity)) invalid('invalid_clarity');
  if (!LIKELIHOODS.includes(body.use_likelihood)) invalid('invalid_use_likelihood');
  if (typeof body.booked_travel_last_12_months !== 'boolean') invalid('invalid_booked_travel');
  const source = body.source === undefined || body.source === '' ? 'direct' : body.source;
  if (typeof source !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(source)) invalid('invalid_source');
  const comment = body.optional_comment === undefined ? '' : body.optional_comment;
  if (typeof comment !== 'string' || comment.length > MAX_COMMENT_LENGTH || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(comment)) invalid('invalid_optional_comment');
  return { request_id: body.request_id.toLowerCase(), survey_version: SURVEY_VERSION, clarity: body.clarity, use_likelihood: body.use_likelihood, booked_travel_last_12_months: body.booked_travel_last_12_months, source, optional_comment: comment.trim() };
}

async function surveyTotals(client, filters) {
  const { where, params } = combinedFilterSql(filters, { totals: true });
  const current = Number((await client.query(`select count(*) from combined_demo_v4_feedback_responses ${where}`, params)).rows[0].count);
  const combined_demo_v3 = Number((await client.query(`select count(*) from combined_demo_feedback_responses ${where}`, params)).rows[0].count);
  const history = (await client.query(`select comprehension_choice is null as free_text,count(*)::int as count from demo_feedback_responses ${where} group by comprehension_choice is null`, params)).rows;
  const package_v1 = Number((await client.query(`select count(*) from package_feedback_responses ${where}`, params)).rows[0].count);
  const free_text_v1 = Number(history.find(row => row.free_text)?.count || 0);
  const multiple_choice_v2 = Number(history.find(row => !row.free_text)?.count || 0);
  return { all: current + combined_demo_v3 + free_text_v1 + multiple_choice_v2 + package_v1, current, combined_demo_v4: current, combined_demo_v3, free_text_v1, multiple_choice_v2, package_v1 };
}

function v4CsvLine(row) {
  // Keep the existing 20-column layout, adding only the V4 optional comment.
  return [row.id, '', '', '', '', '', '', row.source, row.submitted_at, row.created_at, row.updated_at, SURVEY_VERSION,
    row.survey_version, row.request_id, 'clarity', row.clarity, 'use_likelihood', row.use_likelihood, 'booked_travel_last_12_months', row.booked_travel_last_12_months ? 'Yes' : 'No', row.optional_comment].map(csvCell).join(',') + '\r\n';
}

function createCombinedDemoV4FeedbackService({ dbPool, parseFilters, csvHeaders }) {
  async function submit(body) {
    const { optional_comment, ...data } = validateV4Submission(body);
    const columns = Object.keys(data);
    const client = await dbPool.connect();
    try {
      await client.query('begin');
      const row = (await client.query(`insert into combined_demo_v4_feedback_responses(id,${columns.join(',')}) values($1,${columns.map((_, i) => `$${i + 2}`).join(',')}) on conflict(request_id) do nothing returning id`, [crypto.randomUUID(), ...Object.values(data)])).rows[0];
      if (row) {
        if (optional_comment) await client.query('insert into combined_demo_v4_feedback_comments(response_id,comment) values($1,$2)', [row.id, optional_comment]);
      } else {
        const existing = (await client.query(`select ${columns.join(',')},${COMMENT_FIELD} from combined_demo_v4_feedback_responses r where request_id=$1`, [data.request_id])).rows[0];
        if (!existing || columns.some(key => existing[key] !== data[key]) || existing.optional_comment !== optional_comment) throw new FeedbackError(409, 'submission_conflict');
      }
      await client.query('commit');
      return { ok: true };
    } catch (error) { await client.query('rollback'); throw error; } finally { client.release(); }
  }

  // Share the read snapshot across all version totals. V3 always uses its frozen
  // questions and storage; its submission and CSV implementations remain intact.
  async function report(query) {
    const filters = parseFilters(query);
    const v4 = filters.survey_version === SURVEY_VERSION;
    if (!v4 && filters.survey_version !== 'combined_demo_v3') invalid('invalid_survey_version');
    const table = v4 ? 'combined_demo_v4_feedback_responses' : 'combined_demo_feedback_responses';
    const { where, params } = combinedFilterSql(filters);
    const client = await dbPool.connect();
    try {
      await client.query('begin isolation level repeatable read read only');
      const groups = (await client.query(`select source,clarity,use_likelihood,booked_travel_last_12_months,count(*)::int as count from ${table} ${where} group by source,clarity,use_likelihood,booked_travel_last_12_months order by source`, params)).rows;
      const summary = summarizeCombined(groups);
      const pages = Math.max(1, Math.ceil(summary.overall.total / 50));
      const page = Math.min(filters.page, pages);
      const dir = filters.sort === 'oldest' ? 'asc' : 'desc';
      const rows = (await client.query(`select ${FIELDS}${v4 ? ',' + COMMENT_FIELD : ''} from ${table} r ${where} order by submitted_at ${dir},id ${dir} limit 50 offset $${params.length + 1}`, [...params, (page - 1) * 50])).rows;
      const sourceOptions = (await client.query('select source from combined_demo_v4_feedback_responses union select source from combined_demo_feedback_responses union select source from demo_feedback_responses union select source from package_feedback_responses order by source')).rows.map(row => row.source);
      const totals = await surveyTotals(client, filters);
      let commentInfo = {};
      if (v4) {
        const commentCount = Number((await client.query(`select count(*) from combined_demo_v4_feedback_responses r ${where}${where ? ' and' : 'where'} exists(select 1 from combined_demo_v4_feedback_comments where response_id=r.id)`, params)).rows[0].count);
        const comments = rows.filter(row => row.optional_comment).map(row => ({ response_id: row.id, comment: row.optional_comment, source: row.source, submitted_at: row.submitted_at }));
        commentInfo = { optionalComment: OPTIONAL_COMMENT, comments, commentCount };
      }
      await client.query('commit');
      return { ok: true, surveyVersion: filters.survey_version, questions: v4 ? QUESTIONS : V3_QUESTIONS, ...summary, totals, rows, sourceOptions, page, pages, pageSize: 50, ...commentInfo };
    } catch (error) { await client.query('rollback'); throw error; } finally { client.release(); }
  }

  async function* exportCsv(query) {
    const filters = parseFilters(query);
    const { where, params } = combinedFilterSql(filters);
    const client = await dbPool.connect(); let complete = false;
    try {
      await client.query('begin isolation level repeatable read read only');
      const dir = filters.sort === 'oldest' ? 'asc' : 'desc';
      await client.query(`declare combined_v4_feedback_export no scroll cursor for select ${FIELDS},${COMMENT_FIELD} from combined_demo_v4_feedback_responses r ${where} order by submitted_at ${dir},id ${dir}`, params);
      yield '\uFEFF' + [...csvHeaders, ...EXTRA_HEADERS, 'Optional comment'].map(csvCell).join(',') + '\r\n';
      while (true) { const { rows } = await client.query('fetch forward 500 from combined_v4_feedback_export'); if (!rows.length) break; yield rows.map(v4CsvLine).join(''); }
      await client.query('commit'); complete = true;
    } finally { try { if (!complete) await client.query('rollback'); } finally { client.release(); } }
  }
  return { submit, report, exportCsv };
}

module.exports = { SURVEY_VERSION, MAX_COMMENT_LENGTH, QUESTIONS, OPTIONAL_COMMENT, validateV4Submission, surveyTotals, v4CsvLine, createCombinedDemoV4FeedbackService };
