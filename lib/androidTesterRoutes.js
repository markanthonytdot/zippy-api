const crypto = require('node:crypto');
const express = require('express');
const { PartnerAccessError } = require('./partnerAccess');
const SAFE_ERRORS = new Set(['android_testers_unavailable', 'invalid_android_action', 'invitation_not_found',
  'invalid_email', 'email_domain_not_allowed', 'invalid_organization', 'preview_access_inactive',
  'manual_confirmation_required', 'play_eligibility_unconfirmed', 'invitation_in_progress',
  'invitation_cooldown', 'rate_limited', 'mail_unavailable', 'mail_delivery_check_required']);
function sendError(res, error) {
  const safe = SAFE_ERRORS.has(error?.code) && Number.isInteger(error?.status);
  const status = safe ? error.status : 503;
  if (status === 429) res.setHeader('Retry-After', '300');
  return res.status(status).json({ ok: false, error: safe ? error.code : 'android_testers_unavailable' });
}
function input(body) {
  return { action: body?.action, platform: body?.platform, id: body?.id,
    email: body?.email, confirm: body?.confirm === true };
}
function mountOperations(router, service, actor) {
  router.get('/', async (_req, res) => {
    try { res.json(await service.list()); } catch (error) { sendError(res, error); }
  });
  router.post('/', async (req, res) => {
    try { res.json(await service.run(input(req.body), actor(req))); } catch (error) { sendError(res, error); }
  });
  return router;
}
// Browser-facing routes remain behind the existing signed admin session and same-origin check.
function createAndroidTesterAdminRouter({ service }) {
  const router = express.Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!req.zippiAdmin) return res.status(401).json({ ok: false, error: 'admin_auth_required' });
    if (req.method !== 'GET' && (req.get('origin') !== `${req.protocol}://${req.get('host')}` || !req.is('application/json')))
      return res.status(403).json({ ok: false, error: 'admin_origin_required' });
    return next();
  });
  return mountOperations(router, service, req => req.zippiAdmin.actor);
}
function validBridgeSecret(value) { return typeof value === 'string' && value.length >= 32 && value.length <= 512; }
function matches(a, b) {
  if (!validBridgeSecret(a) || !validBridgeSecret(b)) return false;
  const digest = value => crypto.createHash('sha256').update(value).digest();
  return crypto.timingSafeEqual(digest(a), digest(b));
}
// This credential authorizes Android administration only, never OTP verification or JWT minting.
// It is kept on both servers, never in a browser/app, URL, returned configuration or logs.
function createAndroidTesterBridgeRouter({ service, secret, enabled = false }) {
  const router = express.Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!enabled || !validBridgeSecret(secret)) return res.sendStatus(404);
    if (req.get('origin') || !matches(secret, req.get('x-zippi-tester-admin')))
      return res.status(401).json({ ok: false, error: 'admin_auth_required' });
    if (req.method !== 'GET' && !req.is('application/json')) return res.sendStatus(415);
    return next();
  });
  return mountOperations(router, service, req => `staging-admin:${String(req.body?.actor || 'admin').replace(/[^\w.@ -]/g, '').slice(0,80)}`);
}
module.exports = { createAndroidTesterAdminRouter, createAndroidTesterBridgeRouter, validBridgeSecret, sendError, input, SAFE_ERRORS };
