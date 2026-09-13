const express = require('express');
const { Readable } = require('node:stream');
const { pipeline } = require('node:stream/promises');

const PRODUCTION_FEEDBACK_ENDPOINT = 'https://zippy-api-6c59.onrender.com/internal/feedback-read';
const validSecret = value => typeof value === 'string' && value.length >= 32 && value.length <= 512;
const FILTERS = new Set(['source', 'likelihood', 'recent', 'usefulness', 'entry_path', 'from', 'to', 'sort', 'page']);
const READ_PATHS = new Set(['/demo-feedback', '/package-feedback', '/demo-feedback/export.csv', '/package-feedback/export.csv']);

// Browser requests use the existing tester-admin session. Only this server sends
// the read-only credential; browser cookies and authorization are never forwarded.
function createFeedbackAdminRemote({ secret, fetchImpl = globalThis.fetch, endpoint = PRODUCTION_FEEDBACK_ENDPOINT } = {}) {
  const router = express.Router();
  const enabled = validSecret(secret);
  router.use((req, res, next) => {
    if (!READ_PATHS.has(req.path.replace(/\/$/, ''))) return next('router');
    res.set('Cache-Control', 'no-store').set('X-Robots-Tag', 'noindex, nofollow, noarchive');
    if (!req.zippiAdmin) return res.status(401).json({ ok: false, error: 'admin_auth_required' });
    if (!enabled) return res.status(503).json({ ok: false, error: 'feedback_unavailable' });
    if (req.method !== 'GET') return res.status(405).set('Allow', 'GET').json({ ok: false, error: 'method_not_allowed' });
    next();
  });
  for (const name of ['demo-feedback', 'package-feedback']) for (const suffix of ['', '/export.csv']) {
    router.get('/' + name + suffix, async (req, res) => {
      try {
        const query = new URLSearchParams();
        for (const [key, value] of Object.entries(req.query)) {
          if (!FILTERS.has(key) || typeof value !== 'string' || value.length > 128) return res.status(400).json({ ok: false, error: 'invalid_filter' });
          query.set(key, value);
        }
        // The endpoint argument is an isolated-test seam, never browser or env input.
        const response = await fetchImpl(`${endpoint}/${name}${suffix}?${query}`, {
          method: 'GET', redirect: 'error', signal: AbortSignal.timeout(30000),
          headers: { 'x-zippi-feedback-read': secret },
        });
        if (!response.ok) {
          await response.body?.cancel();
          return res.status(response.status === 400 ? 400 : 503).json({ ok: false, error: response.status === 400 ? 'invalid_filter' : 'feedback_unavailable' });
        }
        const expected = suffix ? 'text/csv' : 'application/json';
        if (response.headers.get('content-type')?.split(';')[0].trim() !== expected) {
          await response.body?.cancel();
          throw new Error('unexpected_response');
        }
        if (suffix) {
          res.type('text/csv; charset=utf-8').set('Content-Disposition', `attachment; filename="zippi-${name}-${new Date().toISOString().slice(0, 10)}.csv"`);
          await pipeline(Readable.fromWeb(response.body), res);
        } else res.json(await response.json());
      } catch (_) {
        if (res.headersSent) return res.destroy();
        res.status(503).json({ ok: false, error: 'feedback_unavailable' });
      }
    });
  }
  return { enabled, router };
}

function feedbackNavigation(html, active = '') {
  if (active === 'demo-feedback') html = html.replace('<title>Demo feedback', '<title>Flight demo feedback').replace('<h1>Demo feedback</h1>', '<h1>Flight demo feedback</h1>');
  html = html.replace(/<a\b[^>]*href="\/admin\/(?:demo-feedback|package-feedback)"[^>]*>[\s\S]*?<\/a>/g, '');
  const links = [['demo-feedback', 'Flight Demo Feedback', 'F'], ['package-feedback', 'Package Demo Feedback', 'P']]
    .map(([route, label, icon]) => `<a href="/admin/${route}"${active === route ? ' class="active" aria-current="page"' : ''}><span class="nav-icon">${icon}</span><span>${label}</span></a>`).join('');
  html = html.replace('class="sidebar"', 'class="sidebar has-feedback"');
  return html.replace('</nav>', '<p class="nav-label feedback-nav-label">Feedback</p>' + links + '</nav>');
}
module.exports = { createFeedbackAdminRemote, feedbackNavigation, PRODUCTION_FEEDBACK_ENDPOINT };
