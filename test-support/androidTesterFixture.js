const { Pool } = require('pg');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createPartnerAccessService } = require('../lib/partnerAccess');
const { createAndroidTesterService } = require('../lib/androidTesterService');
async function fixture(t) {
  const connectionString = process.env.PARTNER_TEST_DATABASE_URL;
  if (!connectionString || !['127.0.0.1', 'localhost', '[::1]'].includes(new URL(connectionString).hostname))
    throw new Error('An isolated loopback PARTNER_TEST_DATABASE_URL is required');
  const schema = `android_tester_${crypto.randomBytes(8).toString('hex')}`;
  const root = new Pool({ connectionString, ssl: false });
  await root.query(`create schema ${schema}`);
  const pool = new Pool({ connectionString, ssl: false, options: `-c search_path=${schema}` });
  t.after(async () => { await pool.end(); await root.query(`drop schema ${schema} cascade`); await root.end(); });
  for (const name of ['013_partner_access.sql', '014_tester_invitations.sql', '015_android_tester_eligibility.sql'])
    await pool.query(fs.readFileSync(path.join(__dirname, '../migrations', name), 'utf8'));
  const state = { now: Date.parse('2026-09-12T12:00:00Z'), emails: [], challenges: [], failMail: false, pause: null };
  const secret = 'local-android-tester-fixture-only';
  const { SignJWT, jwtVerify } = await import('jose');
  const key = new TextEncoder().encode(secret);
  const signToken = (sub, claims) => new SignJWT(claims).setSubject(sub).setProtectedHeader({ alg: 'HS256' })
    .setIssuer('zippy-api').setAudience('zippy-ios').setIssuedAt().setExpirationTime('30d').sign(key);
  const mail = { configured: true, async send(message) { state.challenges.push(message); }, async sendInstructions(message) {
    state.emails.push(message); if (state.pause) await state.pause;
    if (state.failMail) throw new Error('PRIVATE_PROVIDER_FIXTURE');
    return { id: 'local-delivery' };
  } };
  const access = createPartnerAccessService({ dbPool: pool, secret, signToken, mailAdapter: mail, now: () => state.now });
  const options = { dbPool: pool, access, mail, secret, enabled: true, now: () => state.now };
  const service = createAndroidTesterService(options);
  const run = (action, extra = {}, actor = 'local-qa-admin') => service.run({ action, platform: 'android', ...extra }, actor);
  return { pool, state, access, service, options, mail, signToken, secret, run, jwtVerify,
    async claims(token) { return (await jwtVerify(token, key, { issuer: 'zippy-api', audience: 'zippy-ios' })).payload; },
    advance(ms = 300001) { state.now += ms; },
    async prepare(email = 'android-qa@heyzippi.test') { return (await run('prepare', { email })).invitation; },
  };
}
module.exports = { fixture };
