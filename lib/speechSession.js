const { randomUUID } = require('node:crypto');
const { createSpeechSessionLimits, speechRequestIp } = require('./speechSessionLimits');
const { parseAllowedOrigins } = require('./strictCors');

const GRANT_URL = 'https://api.deepgram.com/v1/auth/grant';
async function limitedJson(response) {
  if (!response.body?.getReader) throw new Error('Invalid grant body');
  const reader = response.body.getReader(), chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > 16384) throw new Error('Oversized grant body');
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } finally { await reader.cancel().catch(() => {}); }
}

function createSpeechSessionHandler({ env = process.env, fetch = globalThis.fetch, now = Date.now,
  budget = createSpeechSessionLimits({ now }), timeoutMs = 8000, log = record => console.log('[SpeechSession]', JSON.stringify(record)) } = {}) {
  const allowedOrigins = parseAllowedOrigins(env.FLIGHT_SEARCH_CORS_ORIGINS);
  let active = 0;
  return async function speechSession(req, res) {
    const id = randomUUID(), start = now(); let upstreamStatus = null;
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const report = outcome => { try { log({ id, outcome, upstreamStatus, elapsedMs: Math.max(0, now() - start) }); } catch (_) {} };
    const fail = (status, code, message) => { report(code); if (!res.destroyed && !res.writableEnded) res.status(status).json({ ok: false, code, message }); };
    if (req.path && req.path !== '/') return fail(404, 'speech_not_found', 'Speech endpoint not found.');
    const origin = String(req.headers.origin || '');
    if (origin && !allowedOrigins.has(origin)) return fail(403, 'speech_origin_denied', 'Speech is unavailable from this origin.');
    if (origin) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Vary', 'Origin'); }
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-User-ID, X-Request-ID');
      return res.status(204).end();
    }
    if (req.method !== 'POST') return fail(405, 'speech_method_not_allowed', 'Use POST for a speech session.');
    const device = String(req.headers['x-user-id'] || '');
    if (!/^[a-zA-Z0-9_-]{1,96}$/.test(device) || !req.body || Array.isArray(req.body) ||
        typeof req.body !== 'object' || Object.keys(req.body).length || Object.keys(req.query || {}).length) {
      return fail(400, 'speech_request_invalid', 'Please restart voice input.');
    }
    const key = String(env.DEEPGRAM_SERVER_API_KEY || '').trim();
    if (!key) return fail(503, 'speech_unavailable', 'Voice is temporarily unavailable. Please try again.');
    const decision = budget.take({ device, ip: speechRequestIp(req, env.RENDER === 'true') });
    if (!decision.ok) {
      res.setHeader('Retry-After', String(decision.retryAfter));
      return fail(429, 'speech_rate_limited', 'Voice is busy. Please wait a moment and try again.');
    }
    if (active >= 8) return fail(503, 'speech_busy', 'Voice is busy. Please try again shortly.');
    const controller = new AbortController(); let timedOut = false;
    const cancel = () => controller.abort();
    const closed = () => { if (!res.writableEnded) cancel(); };
    req.once('aborted', cancel); res.once('close', closed);
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    active++;
    try {
      const response = await fetch(GRANT_URL, { method: 'POST', redirect: 'error',
        headers: { Authorization: `Token ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ttl_seconds: 30 }), signal: controller.signal });
      upstreamStatus = response.status;
      if (!response.ok) { await response.body?.cancel().catch(() => {}); return fail(503, 'speech_unavailable', 'Voice is temporarily unavailable. Please try again.'); }
      const data = await limitedJson(response);
      const remaining = Math.floor(Number(data.expires_in) - Math.ceil((now() - start) / 1000));
      if (typeof data.access_token !== 'string' || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(data.access_token) ||
          data.access_token.length > 8192 || data.access_token === key || !Number.isFinite(remaining) || remaining < 1 || remaining > 30) {
        return fail(503, 'speech_response_invalid', 'Voice is temporarily unavailable. Please try again.');
      }
      if (controller.signal.aborted || req.aborted || res.destroyed) { report(timedOut ? 'speech_timeout' : 'speech_cancelled'); return; }
      report('issued');
      res.status(200).json({ ok: true, accessToken: data.access_token, tokenType: 'Bearer', expiresInSeconds: remaining });
    } catch (_) {
      if (req.aborted || res.destroyed) report('speech_cancelled');
      else fail(503, timedOut ? 'speech_timeout' : 'speech_unavailable', 'Voice could not connect. Please try again.');
    } finally {
      clearTimeout(timer); req.off('aborted', cancel); res.off('close', closed); active--;
    }
  };
}

module.exports = { createSpeechSessionHandler, limitedJson };
