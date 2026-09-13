const express = require('express');
const { Readable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { FeedbackError } = require('./demoFeedback');
const { createDemoFeedbackPublicRouter } = require('./demoFeedbackRoutes');
const { createPackageFeedbackService, parsePackageFilters } = require('./packageFeedback');

function installPackageFeedbackRuntime(app, { dbPool, secret, environment = process.env }) {
  if (environment.ZIPPI_PACKAGE_FEEDBACK_ENABLED !== 'true') return null;
  const service = createPackageFeedbackService({ dbPool, secret });
  const allowedOrigins = environment.PACKAGE_FEEDBACK_CORS_ORIGINS;
  app.use('/v1/package-feedback/events', createDemoFeedbackPublicRouter({ service: { submit: service.recordClick }, allowedOrigins }));
  app.use('/v1/package-feedback', createDemoFeedbackPublicRouter({ service, allowedOrigins }));
  return service;
}
function createPackageFeedbackAdminRouter({ service }) {
  const router = express.Router();
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store').set('X-Robots-Tag', 'noindex, nofollow, noarchive');
    if (!req.zippiAdmin) return res.status(401).json({ ok: false, error: 'admin_auth_required' });
    next();
  });
  function failure(res, error) {
    if (res.headersSent) return res.destroy();
    return res.status(error instanceof FeedbackError ? error.status : 503).json({ ok: false, error: error instanceof FeedbackError ? error.code : 'feedback_unavailable' });
  }
  router.get('/', async (req, res) => { try { res.json(await service.report(req.query)); } catch (error) { failure(res, error); } });
  router.get('/export.csv', async (req, res) => {
    try {
      parsePackageFilters(req.query);
      const chunks = service.exportCsv(req.query); const first = await chunks.next();
      res.type('text/csv; charset=utf-8').set('Content-Disposition', `attachment; filename="zippi-package-feedback-${new Date().toISOString().slice(0, 10)}.csv"`);
      await pipeline(Readable.from((async function* () {
        try { if (!first.done) yield first.value; yield* chunks; } finally { await chunks.return(); }
      })()), res);
    } catch (error) { failure(res, error); }
  });
  return router;
}
module.exports = { installPackageFeedbackRuntime, createPackageFeedbackAdminRouter };
