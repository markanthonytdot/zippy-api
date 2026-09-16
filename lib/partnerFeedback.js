const express = require('express');
const { createStrictCorsMiddleware } = require('./strictCors');

// These two records are the documented production v4 acceptance submissions.
// Keep the exclusions read-only: never remove or rewrite research records.
const QA_RESPONSE_IDS = Object.freeze([
  '047e3ade-5ff0-4d8f-afe5-3cc5d5cc643d',
  '6aa4d0ac-0401-4b5d-a534-d4e085f60cd6',
]);
const INTERNAL_SOURCE = '(^|[-_])(qa|test|testing|local|localhost|synthetic|internal|staff|dev|development|preview|smoke|e2e|automation|automated)([-_0-9]|$)';
const AGGREGATE_SQL = `
  select
    round(100.0 * count(*) filter (where clarity in ('Very clear','Somewhat clear'))
      / nullif(count(*),0), 1) as understanding,
    round(100.0 * count(*) filter (where use_likelihood in ('Definitely','Probably'))
      / nullif(count(*),0), 1) as intent
  from combined_demo_v4_feedback_responses
  where survey_version = 'combined_demo_v4'
    and source !~* $1
    and not (id = any($2::uuid[]))
`;

function createPartnerFeedbackService({ dbPool, now = Date.now }) {
  let cached, expires = 0, pending;
  return async function percentages() {
    if (cached && now() < expires) return cached;
    if (pending) return pending;
    pending = (async () => {
      const client = await dbPool.connect();
      try {
        await client.query('begin read only');
        const { rows } = await client.query(AGGREGATE_SQL, [INTERNAL_SOURCE, QA_RESPONSE_IDS]);
        await client.query('commit');
        const percent = value => value == null ? null : Number(value);
        cached = Object.freeze({ understandingPercent: percent(rows[0].understanding), intentPercent: percent(rows[0].intent) });
        expires = now() + 60000;
        return cached;
      } catch (error) { await client.query('rollback'); throw error; }
      finally { client.release(); }
    })();
    try { return await pending; } finally { pending = null; }
  };
}

function createPartnerFeedbackRouter({ dbPool, allowedOrigins, now }) {
  const router = express.Router();
  const percentages = createPartnerFeedbackService({ dbPool, now });
  router.use((_req, res, next) => { res.set('X-Robots-Tag', 'noindex, nofollow'); next(); });
  router.use(createStrictCorsMiddleware({ allowedOrigins, allowedMethods: 'GET, HEAD, OPTIONS' }));
  router.get('/', async (req, res) => {
    // No filters or pagination: prevent public access to individual cohorts.
    if (Object.keys(req.query).length) return res.status(400).set('Cache-Control', 'no-store').json({ error: 'filters_not_supported' });
    try { res.set('Cache-Control', 'public, max-age=60').json(await percentages()); }
    catch { res.status(503).set('Cache-Control', 'no-store').json({ error: 'feedback_unavailable' }); }
  });
  router.all(/.*/, (_req, res) => res.status(405).set('Allow', 'GET, HEAD, OPTIONS').json({ error: 'method_not_allowed' }));
  return router;
}

module.exports = { QA_RESPONSE_IDS, INTERNAL_SOURCE, AGGREGATE_SQL, createPartnerFeedbackService, createPartnerFeedbackRouter };
