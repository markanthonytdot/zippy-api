const { createPartnerAccessService, PartnerAccessError } = require('./partnerAccess');
const { registerPartnerAccessRoutes, createPartnerAccessEnforcement } = require('./partnerAccessRoutes');
const { createResendMailAdapter } = require('./partnerAccessResendMail');
const { createAndroidTesterService, DEFAULT_ORGANIZATION } = require('./androidTesterService');
const { createAndroidTesterBridgeRouter } = require('./androidTesterRoutes');

function installAndroidTesterRuntime(app, { dbPool, signToken, verifyUser, secret, env = process.env, mailAdapter }) {
  const enabled = env.ZIPPI_ANDROID_TESTER_AUTH_ENABLED === 'true';
  const mail = mailAdapter || createResendMailAdapter(env);
  // No reviewer override, staging connection, development mailbox or staging token trust.
  const access = createPartnerAccessService({ dbPool, secret, signToken, mailAdapter: mail });
  if (enabled) {
    app.use('/partner-access', (req, res, next) => {
      if (req.method === 'POST' && req.body?.platform !== 'android') return res.status(400).json({ ok: false, error: 'invalid_platform' });
      if (req.authClaims?.auth_method === 'partner_preview' && req.authClaims.platform !== 'android') return res.status(401).json({ ok: false, error: 'invalid_auth' });
      return next();
    });
    registerPartnerAccessRoutes(app, { service: access, required: false, verifyUser });
  }
  app.use(createPartnerAccessEnforcement({ required: false, service: { async status(claims) {
    if (!enabled || claims?.platform !== 'android') throw new PartnerAccessError(503, 'partner_access_unavailable');
    return access.status(claims);
  } } }));
  const service = createAndroidTesterService({ dbPool, access, mail, secret, enabled,
    organizationId: env.ZIPPI_ANDROID_TESTER_ORGANIZATION_ID || DEFAULT_ORGANIZATION,
    durationDays: Number(env.ZIPPI_ANDROID_TESTER_DURATION_DAYS || 7) });
  app.use('/internal/android-tester-admin', createAndroidTesterBridgeRouter({ service,
    secret: env.ZIPPI_ANDROID_TESTER_BRIDGE_SECRET, enabled: enabled && env.ZIPPI_ANDROID_TESTER_BRIDGE_ENABLED === 'true' }));
  return { ...service, deleteAccount(claims) {
    if (claims?.auth_method !== 'partner_preview') return Promise.resolve({ deleted: false });
    if (claims.platform !== 'android') throw new PartnerAccessError(401, 'invalid_auth');
    return access.deleteAccount(claims);
  } };
}
module.exports = { installAndroidTesterRuntime };
