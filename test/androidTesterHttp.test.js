const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs');
const vm = require('node:vm');
const { fixture } = require('../test-support/androidTesterFixture');
const { installAndroidTesterRuntime } = require('../lib/androidTesterRuntime');
const { createAndroidTesterRemote } = require('../lib/androidTesterRemote');
const { createAdminDashboardRouter, createAdminSessionToken } = require('../lib/adminDashboard');
const BRIDGE = 'local-fixture-bridge-credential-not-for-deployment';
async function listen(t, app) {
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return `http://127.0.0.1:${server.address().port}`;
}
// Execute the actual production signer and middleware bodies, rather than a parallel claim fixture.
async function productionAuth(secret) {
  const source = fs.readFileSync(require.resolve('../server.js'), 'utf8');
  function declaration(start, end) { const at = source.indexOf(start); assert.ok(at >= 0); return source.slice(at, source.indexOf(end, at)); }
  const context = vm.createContext({ JWT_SECRET: secret, JWT_ISSUER: 'zippy-api', JWT_AUDIENCE: 'zippy-ios', TextEncoder,
    getJose: async () => import('jose') });
  vm.runInContext(declaration('async function signZippyToken(', '\nfunction normalizedApplePrivateKey'), context);
  vm.runInContext(declaration('async function hydrateUserIdFromAuth(', '\nfunction hotelAwareApiLimit'), context);
  vm.runInContext(declaration('async function verifyBearerUserId(', '\nasync function requireVerifiedUser'), context);
  return context;
}
test('signed dashboard → private bridge → production invitation → v10 OTP → entitlement/revoke', async t => {
  const f = await fixture(t); const auth = await productionAuth(f.secret);
  const production = express(); production.use(express.json());
  production.use(async (req, _res, next) => { await auth.hydrateUserIdFromAuth(req); next(); });
  const service = installAndroidTesterRuntime(production, { dbPool: f.pool, secret: f.secret,
    signToken: auth.signZippyToken, mailAdapter: f.mail,
    verifyUser: async (req, res) => { const user = await auth.verifyBearerUserId(req); if (!user) res.sendStatus(401); return user; },
    env: { ZIPPI_ANDROID_TESTER_AUTH_ENABLED: 'true', ZIPPI_ANDROID_TESTER_BRIDGE_ENABLED: 'true', ZIPPI_ANDROID_TESTER_BRIDGE_SECRET: BRIDGE } });
  production.get('/v1/flights/test-read', (_req, res) => res.json({ ok: true }));
  production.delete('/me/account', async (req,res) => res.json(await service.deleteAccount(req.authClaims)));
  const url = await listen(t, production);
  const remote = createAndroidTesterRemote({ endpoint: `${url}/internal/android-tester-admin`,
    env: { ZIPPI_ANDROID_TESTER_REMOTE_ENABLED: 'true', ZIPPI_ANDROID_TESTER_BRIDGE_SECRET: BRIDGE } });
  const dashboard = express(); dashboard.use(express.json());
  dashboard.use('/admin', createAdminDashboardRouter({ androidTesterService: remote, sessionSecret: 'local-admin-session' }));
  const admin = await listen(t, dashboard);
  const cookie = `__Secure-zippi_admin_session=${createAdminSessionToken('local-admin-session', Date.now(), 'local-qa')}`;
  async function run(body, extra = {}) {
    const response = await fetch(`${admin}/admin/api/android-testers`, { method: 'POST', headers: { cookie, origin: admin, 'content-type': 'application/json', ...extra }, body: JSON.stringify({ platform: 'android', ...body }) });
    return { status: response.status, body: await response.json() };
  }
  await t.test('signed admin and same-origin required; bridge credentials never returned', async () => {
    assert.equal((await fetch(`${admin}/admin/api/android-testers`)).status, 401);
    assert.equal((await run({ action: 'prepare', email: 'qa@heyzippi.test' }, { origin: 'https://untrusted.example' })).status, 403);
    const list = await fetch(`${admin}/admin/api/android-testers`, { headers: { cookie } });
    assert.equal(list.headers.get('cache-control'), 'no-store');
    const body = await list.json(); assert.equal(body.config.authority, 'production'); assert.ok(!JSON.stringify(body).includes(BRIDGE));
    for (const headers of [{}, { 'x-zippi-tester-admin': 'wrong' }, { 'x-zippi-tester-admin': BRIDGE, origin: admin }])
      assert.equal((await fetch(`${url}/internal/android-tester-admin`, { headers })).status, 401);
  });
  let id;
  await t.test('prepare, manual eligibility, one welcome and untrusted fields cannot expand access', async () => {
    const prepared = await run({ action: 'prepare', email: 'android-http-qa@heyzippi.test', durationDays: 999, features: { checkout: true }, organizationId: 'forged' });
    assert.equal(prepared.status, 200); id = prepared.body.invitation.id;
    assert.equal(prepared.body.invitation.playEligibility, 'not_confirmed'); assert.equal(f.state.emails.length, 0);
    assert.equal((await run({ action: 'send', id })).status, 409);
    assert.equal((await run({ action: 'confirm', id })).status, 400);
    assert.equal((await run({ action: 'confirm', id, confirm: true })).status, 200); assert.equal(f.state.emails.length, 0);
    assert.equal((await run({ action: 'send', id })).status, 200);
    assert.equal((await run({ action: 'send', id })).status, 200); assert.equal(f.state.emails.length, 1);
    assert.equal((await run({ action: 'prepare', platform: 'ios', email: 'ios@heyzippi.test' })).status, 400);
  });
  let token;
  await t.test('exact Android wire payload verifies; claims retained by production signer and hydration', async () => {
    const config = await (await fetch(`${url}/partner-access/config`)).json(); assert.equal(config.required, false);
    const request = { email: 'android-http-qa@heyzippi.test', platform: 'android', deviceId: 'local-fixture', appVersion: '1.0.7' };
    const post = (path, body) => fetch(`${url}/partner-access/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal((await post('request-code', request)).status, 202);
    const code = f.state.challenges.at(-1).code; assert.match(code, /^\d{6}$/);
    const verified = await (await post('verify-code', { ...request, code })).json();
    assert.equal(verified.ok, true); token = verified.token;
    const req = { headers: { authorization: `Bearer ${token}` } }; await auth.hydrateUserIdFromAuth(req);
    assert.equal(req.authClaims.auth_method, 'partner_preview'); assert.equal(req.authClaims.platform, 'android');
    assert.equal(req.authClaims.uid, req.authClaims.sub); assert.equal(req.userIdVerified, true);
    assert.equal(verified.partnerAccess.features.checkout, false); assert.equal(verified.partnerAccess.features.combinedTrip, true);
    assert.equal((await post('verify-code', { ...request, code })).status, 401);
    assert.equal((await post('request-code', { ...request, platform: 'ios' })).status, 400);
    const status = await (await fetch(`${url}/partner-access/status`, { headers: { authorization: `Bearer ${token}` } })).json();
    assert.equal(status.access, 'active'); assert.equal(status.refreshAfterSeconds, 60);
  });
  await t.test('revoked token denied immediately; Google, Apple and anonymous behavior preserved', async () => {
    assert.equal((await fetch(`${url}/v1/flights/test-read`, { headers: { authorization: `Bearer ${token}` } })).status, 200);
    assert.equal((await run({ action: 'revoke', id })).status, 200);
    assert.equal((await fetch(`${url}/v1/flights/test-read`, { headers: { authorization: `Bearer ${token}` } })).status, 403);
    assert.equal((await service.list()).invitations[0].playEligibility, 'confirmed');
    for (const sub of [null, 'google:local', 'apple:local']) {
      const headers = sub ? { authorization: `Bearer ${await auth.signZippyToken(sub)}` } : {};
      assert.equal((await fetch(`${url}/v1/flights/test-read`, { headers })).status, 200);
    }
    const forged = Buffer.from(JSON.stringify({ auth_method: 'partner_preview', sub: 'partner:forged' })).toString('base64url');
    assert.equal((await fetch(`${url}/v1/flights/test-read`, { headers: { authorization: `Bearer e30.${forged}.bad` } })).status, 401);
  });
  await t.test('staging-signed preview token is rejected; account deletion removes only the production identity', async () => {
    const id = (await run({action:'prepare',email:'delete-http-qa@heyzippi.test'})).body.invitation.id;
    const row = (await f.pool.query('select person_id from tester_invitations where id=$1',[id])).rows[0];
    const claims = {auth_method:'partner_preview',platform:'android',partner_invite_id:row.person_id};
    const subject = `partner:${row.person_id}`;
    const otherAuth = await productionAuth('different-staging-fixture-key');
    const stageToken = await otherAuth.signZippyToken(subject,claims);
    assert.equal((await fetch(`${url}/v1/flights/test-read`,{headers:{authorization:`Bearer ${stageToken}`}})).status,401);
    const ownToken = await auth.signZippyToken(subject,claims);
    assert.equal((await fetch(`${url}/me/account`,{method:'DELETE',headers:{authorization:`Bearer ${ownToken}`}})).status,200);
    assert.equal((await f.pool.query('select count(*) from partner_people where id=$1',[row.person_id])).rows[0].count,'0');
    assert.equal((await f.pool.query('select count(*) from tester_invitations where id=$1',[id])).rows[0].count,'0');
    assert.equal((await fetch(`${url}/v1/flights/test-read`,{headers:{authorization:`Bearer ${ownToken}`}})).status,403);
    const source=fs.readFileSync(require.resolve('../server.js'),'utf8');
    const deletion=source.slice(source.indexOf('app.delete("/me/account"'));
    assert.match(deletion,/await androidTesterService.deleteAccount\(req.authClaims\)/);
  });
});
test('disabled production auth leaves guests unchanged and exposes no bridge', async t => {
  const app = express(); app.use(express.json());
  installAndroidTesterRuntime(app, { env: {}, dbPool: null, secret: '', mailAdapter: { configured: false } });
  app.get('/v1/flights/test-read', (_req,res) => res.json({ok:true}));
  const url = await listen(t, app);
  assert.equal((await fetch(`${url}/v1/flights/test-read`)).status, 200);
  assert.equal((await fetch(`${url}/internal/android-tester-admin`)).status, 404);
  assert.equal((await fetch(`${url}/partner-access/config`)).status, 404);
});
test('remote outage/redaction/redirect safety never falls back to staging', async () => {
  const env = { ZIPPI_ANDROID_TESTER_REMOTE_ENABLED: 'true', ZIPPI_ANDROID_TESTER_BRIDGE_SECRET: BRIDGE };
  for (const fetchImpl of [async () => { throw new Error(BRIDGE); }, async () => ({ ok: true, json: async () => ({ config: { authority: 'staging' } }) }),
    async () => ({ ok: false, status: 500, json: async () => ({ error: BRIDGE }) })]) {
    const remote = createAndroidTesterRemote({ env, fetchImpl });
    await assert.rejects(remote.run({ action: 'prepare', platform: 'android' }, 'qa'), error => error.code === 'android_testers_unavailable' && !String(error).includes(BRIDGE));
  }
  let calls = 0;
  const remote = createAndroidTesterRemote({ env, fetchImpl: async (url, options) => {
    calls++; assert.equal(options.redirect, 'error'); assert.ok(options.signal); assert.equal(new URL(url).hostname, 'zippy-api-6c59.onrender.com');
    assert.equal(JSON.parse(options.body).url, undefined); return { ok: true, json: async () => ({ invitation: { authority: 'production' } }) };
  } });
  await remote.run({ platform: 'android', action: 'prepare', url: 'http://forged', features: { checkout: true } }, 'qa'); assert.equal(calls, 1);
});
