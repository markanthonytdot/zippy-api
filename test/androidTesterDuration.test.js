const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture } = require('../test-support/androidTesterFixture');
const { input } = require('../lib/androidTesterRoutes');
const day = 86400000;
for (const days of [1, 3, 7, 14, 30, 2, 5, 10, 90, undefined]) test(`Android new access: ${days ?? 'default 7'} days, exact server UTC`, async t => {
  const f = await fixture(t);
  const { invitation } = await f.run('prepare', { email: 'duration@heyzippi.test', ...(days === undefined ? {} : { durationDays: days }) });
  const p = (await f.pool.query('select starts_at,expires_at from partner_people')).rows[0];
  assert.equal(+p.starts_at, f.state.now); assert.equal(+p.expires_at - +p.starts_at, (days ?? 7) * day);
  assert.equal(invitation.access, 'active'); assert.equal(+new Date(invitation.expiresAt), +p.expires_at);
  assert.equal(f.state.emails.length + f.state.challenges.length, 0);
});
test('invalid durations fail before provisioning including coercible strings and null', async t => {
  const f = await fixture(t);
  for (const durationDays of [0, -1, 1.5, 91, 999, '', ' ', 'abc', '2', null, true, [], {}])
    await assert.rejects(f.run('prepare', { email: 'invalid@heyzippi.test', durationDays }), { code: 'invalid_duration' });
  assert.equal((await f.pool.query('select count(*) from partner_people')).rows[0].count, '0');
});
test('one-day expiry survives re-prepare, Play actions, resend, OTP verification and returning session', async t => {
  const f = await fixture(t); const row = (await f.run('prepare', { email: 'duration@heyzippi.test', durationDays: 1 })).invitation;
  const expiry = row.expiresAt;
  for (const durationDays of [2, 5, 10, 90]) {
    f.advance(); assert.equal((await f.run('prepare', { email: row.email, durationDays })).invitation.expiresAt, expiry);
  }
  for (const action of ['confirm', 'unconfirm', 'confirm']) assert.equal((await f.run(action, { id: row.id, confirm: true })).invitation.expiresAt, expiry);
  await f.run('send', { id: row.id }); f.advance(); await f.run('resend', { id: row.id, durationDays: 30 });
  const req = { email: row.email, platform: 'android', ip: '192.0.2.1' };
  await f.access.requestCode(req); f.advance(61000); await f.access.requestCode(req);
  assert.equal((await f.access.requestCode(req)).codeExpiresInSeconds, 600);
  const verified = await f.access.verifyCode({ ...req, code: f.state.challenges.at(-1).code });
  const claims = await f.claims(verified.token);
  assert.equal(verified.partnerAccess.expiresAt, expiry);
  for (let i = 0; i < 3; i++) { f.advance(); assert.equal((await f.access.status(claims)).expiresAt, expiry); }
  f.state.now = Date.parse(expiry) - 1; assert.equal((await f.access.status(claims)).access, 'active');
  f.state.now++; const ended = await f.access.status(claims); assert.equal(ended.access, 'expired');
  assert.equal(ended.features.flights, false); assert.equal(ended.features.hotels, false);
  const sent = f.state.challenges.length; await f.access.requestCode(req); assert.equal(f.state.challenges.length, sent);
  await assert.rejects(f.run('prepare', { email: row.email, durationDays: 30 }), { code: 'preview_access_inactive' });
  await assert.rejects(f.run('resend', { id: row.id }), { code: 'preview_access_inactive' });
  assert.equal((await f.service.list()).invitations[0].expiresAt, expiry);
});
test('explicit extension uses current expiry or now and rejects stale double extension', async t => {
  const f = await fixture(t); const row = (await f.run('prepare', { email: 'extend@heyzippi.test', durationDays: 1 })).invitation;
  await f.run('confirm', { id: row.id, confirm: true });
  const input = { id: row.id, durationDays: 5, expectedExpiresAt: row.expiresAt, confirm: true };
  await assert.rejects(f.run('extend', { ...input, confirm: false }), { code: 'manual_confirmation_required' });
  const next = (await f.run('extend', input)).invitation;
  assert.equal(Date.parse(next.expiresAt), Date.parse(row.expiresAt) + 5 * day);
  await assert.rejects(f.run('extend', input), { code: 'expiry_changed' });
  f.state.now = Date.parse(next.expiresAt) + 1000;
  const restored = (await f.run('extend', { ...input, expectedExpiresAt: next.expiresAt, durationDays: 1 })).invitation;
  assert.equal(Date.parse(restored.expiresAt), f.state.now + day); assert.equal(restored.access, 'active');
  assert.equal(restored.playEligibility, 'confirmed'); assert.equal(restored.emailStatus, 'not_sent');
  assert.equal(f.state.emails.length + f.state.challenges.length, 0);
  assert.equal((await f.pool.query("select count(*) from partner_access_audit where event='access_extended'")).rows[0].count, '2');
});
for (const action of ['revoke', 'disable']) test(`${action} stays blocked even after explicit extension`, async t => {
  const f = await fixture(t); const row = await f.prepare();
  const before = (await f.run(action, { id: row.id })).invitation;
  assert.equal(before.access, action === 'disable' ? 'disabled' : 'revoked');
  const result = (await f.run('extend', { id: row.id, durationDays: 90, confirm: true, expectedExpiresAt: before.expiresAt })).invitation;
  assert.equal(result.access, before.access);
  await f.access.requestCode({ email: row.email, platform: 'android', ip: '192.0.2.3' }); assert.equal(f.state.challenges.length, 0);
});
test('wire admission accepts bounded duration fields only on their intended operations', () => {
  assert.equal(input({ action: 'prepare', durationDays: 1 }).durationDays, 1);
  for (const action of ['send', 'resend', 'confirm', 'revoke', 'disable']) {
    const v = input({ action, durationDays: 30, expectedExpiresAt: 'injected', expiresAt: 'injected' });
    assert.equal(v.durationDays, undefined); assert.equal(v.expectedExpiresAt, undefined); assert.equal(v.expiresAt, undefined);
  }
});

test('custom duration independently protects new access and extension against invalid or alternate-field bypass', async t => {
  const f=await fixture(t);const row=(await f.run('prepare',{email:'custom-safety@example.test',durationDays:2})).invitation;
  const person=(await f.pool.query('select * from partner_people')).rows[0];
  for(const durationDays of [0,-1,91,2.5,'','abc','2',null]) {
    await assert.rejects(f.run('extend',{id:row.id,durationDays,confirm:true,expectedExpiresAt:row.expiresAt}),{code:'invalid_duration'});
    await assert.rejects(f.access.changePerson(person.id,'extend',{durationDays},'test'),{code:'invalid_duration'});
    await assert.rejects(f.access.createPerson({email:'invalid@example.test',organizationId:person.organization_id,durationDays},'test'),{code:'invalid_duration'});
  }
  await assert.rejects(f.access.changePerson(person.id,'extend',{durationDays:91,expiresAt:new Date(f.state.now+5*day).toISOString()},'test'),{code:'invalid_duration'});
  await assert.rejects(f.access.changePerson(person.id,'extend',{expiresAt:'2099-01-01T00:00:00Z'},'test'),{code:'invalid_expiry'});
  await assert.rejects(f.access.createPerson({email:'invalid@example.test',organizationId:person.organization_id,expiresAt:'2099-01-01T00:00:00Z'},'test'),{code:'invalid_expiry'});
  assert.equal((await f.service.list()).invitations[0].expiresAt,row.expiresAt);
  assert.equal(f.state.emails.length+f.state.challenges.length,0);
});
