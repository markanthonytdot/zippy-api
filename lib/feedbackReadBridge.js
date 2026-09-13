const crypto = require('node:crypto');
const express = require('express');
const { Readable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { FeedbackError, parseFilters } = require('./demoFeedback');
const { parsePackageFilters } = require('./packageFeedback');

const FEEDBACK_ADMIN_ORIGIN = 'https://zippi-partner-staging.onrender.com';
function validReadSecret(value) {
  return typeof value === 'string' && value.length >= 32 && value.length <= 512;
}
function readSecretMatches(expected, supplied) {
  if (!validReadSecret(expected) || !validReadSecret(supplied)) return false;
  const digest = value => crypto.createHash('sha256').update(value).digest();
  return crypto.timingSafeEqual(digest(expected), digest(supplied));
}

// A separate server credential permits only these four feedback reads. It never
// grants a Zippi Admin session, tester access, survey writes, or other API access.
function createFeedbackReadBridgeRouter({ secret, flight, packages }) {
  const router = express.Router();
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store').set('X-Robots-Tag', 'noindex, nofollow, noarchive');
    if (!validReadSecret(secret)) return res.sendStatus(404);
    if (req.get('origin') || req.get('sec-fetch-site') || !readSecretMatches(secret, req.get('x-zippi-feedback-read'))) {
      return res.status(401).json({ ok: false, error: 'admin_auth_required' });
    }
    if (req.method !== 'GET') return res.status(405).set('Allow', 'GET').json({ ok: false, error: 'method_not_allowed' });
    next();
  });
  function failure(res, error) {
    if (res.headersSent) return res.destroy();
    return res.status(error instanceof FeedbackError ? error.status : 503)
      .json({ ok: false, error: error instanceof FeedbackError ? error.code : 'feedback_unavailable' });
  }
  for (const [name, service, validate] of [['demo-feedback', flight, parseFilters], ['package-feedback', packages, parsePackageFilters]]) {
    router.get('/' + name, async (req, res) => {
      try {
        if (!service) return res.status(503).json({ ok: false, error: 'feedback_unavailable' });
        res.json(await service.report(req.query));
      } catch (error) { failure(res, error); }
    });
    router.get('/' + name + '/export.csv', async (req, res) => {
      try {
        validate(req.query);
        if (!service) return res.status(503).json({ ok: false, error: 'feedback_unavailable' });
        const chunks = service.exportCsv(req.query); const first = await chunks.next();
        res.type('text/csv; charset=utf-8').set('Content-Disposition', `attachment; filename="zippi-${name}-${new Date().toISOString().slice(0, 10)}.csv"`);
        await pipeline(Readable.from((async function* () {
          try { if (!first.done) yield first.value; yield* chunks; }
          finally { await chunks.return(); }
        })()), res);
      } catch (error) { failure(res, error); }
    });
  }
  router.use((_req, res) => res.sendStatus(404));
  return router;
}
module.exports = { createFeedbackReadBridgeRouter, FEEDBACK_ADMIN_ORIGIN };
