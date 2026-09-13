const express = require('express');
const { Readable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { FeedbackError, parseFilters } = require('./demoFeedback');
const { createStrictCorsMiddleware, parseAllowedOrigins } = require('./strictCors');

function failure(res, error) {
  if (res.headersSent) return res.destroy();
  if (error.status === 429) res.set('Retry-After', '900');
  return res.status(error instanceof FeedbackError ? error.status : 503).json({ ok: false, error: error instanceof FeedbackError ? error.code : 'feedback_unavailable' });
}
function createDemoFeedbackPublicRouter({ service, allowedOrigins }) {
  const router = express.Router(); const origins = parseAllowedOrigins(allowedOrigins);
  router.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); res.set('X-Robots-Tag', 'noindex, nofollow'); next(); });
  router.use((req, res, next) => {
    if (req.headers.origin && !origins.has(req.headers.origin)) return res.status(403).json({ ok: false, error: 'origin_denied' });
    next();
  });
  router.use(createStrictCorsMiddleware({ allowedOrigins, allowedMethods: 'POST, OPTIONS' }));
  router.post('/', async (req, res) => {
    try {
      if (!req.is('application/json')) throw new FeedbackError(415, 'json_required');
      if (Buffer.byteLength(JSON.stringify(req.body || {})) > 8192) throw new FeedbackError(413, 'submission_too_large');
      return res.status(201).json(await service.submit(req.body, req.ip || req.socket?.remoteAddress));
    } catch (error) { return failure(res, error); }
  });
  router.all(/.*/, (_req, res) => res.status(405).set('Allow', 'POST, OPTIONS').json({ ok: false, error: 'method_not_allowed' }));
  return router;
}
// Mount only AFTER the existing admin authorization middleware.
function createDemoFeedbackAdminRouter({ service }) {
  const router = express.Router();
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store'); res.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
    if (!req.zippiAdmin) return res.status(401).json({ ok: false, error: 'admin_auth_required' });
    next();
  });
  router.get('/', async (req, res) => { try { res.json(await service.report(req.query)); } catch (error) { failure(res, error); } });
  router.get('/export.csv', async (req, res) => {
    try {
      parseFilters(req.query);
      const chunks = service.exportCsv(req.query);
      // Open the read snapshot before sending download headers so setup failures are JSON errors.
      const first = await chunks.next();
      res.type('text/csv; charset=utf-8').set('Content-Disposition', `attachment; filename="zippi-demo-feedback-${new Date().toISOString().slice(0, 10)}.csv"`);
      await pipeline(Readable.from((async function* () {
        try { if (!first.done) yield first.value; yield* chunks; }
        finally { await chunks.return(); }
      })()), res);
    } catch (error) { failure(res, error); }
  });
  return router;
}
module.exports = { createDemoFeedbackPublicRouter, createDemoFeedbackAdminRouter };
