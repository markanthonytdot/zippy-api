const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture } = require('../test-support/androidTesterFixture');
const { createAndroidTesterService } = require('../lib/androidTesterService');
const { createPartnerAccessEnforcement } = require('../lib/partnerAccessRoutes');

test('Android tester access and manual distribution lifecycle', async t => {
  await t.test('prepare reuses normalized identity; no eligibility or delivery side effect', async t => {
    const f = await fixture(t); const first = await f.prepare(' QA+Android@HEYZIPPI.TEST '); const second = await f.prepare('qa+android@heyzippi.test');
    assert.equal(first.id, second.id); assert.equal(first.playEligibility, 'not_confirmed');
    assert.equal(first.access, 'active'); assert.equal(first.emailStatus, 'not_sent');
    assert.equal(f.state.emails.length, 0); assert.equal(f.state.challenges.length, 0);
    assert.equal((await f.pool.query('select count(*) from partner_people')).rows[0].count, '1');
    assert.equal((await f.pool.query('select count(*) from partner_verifications')).rows[0].count, '0');
  });
  await t.test('send/retry/resend cannot skip manual Play confirmation', async t => {
    const f = await fixture(t); const row = await f.prepare();
    for (const action of ['send', 'retry', 'resend']) await assert.rejects(f.run(action, { id: row.id }), { code: 'play_eligibility_unconfirmed' });
    await assert.rejects(f.run('confirm', { id: row.id }), { code: 'manual_confirmation_required' });
    assert.equal(f.state.emails.length, 0);
  });
  await t.test('manual confirmation sends nothing; repeated send and prepare deliver once', async t => {
    const f = await fixture(t); const row = await f.prepare();
    await f.run('confirm', { id: row.id, confirm: true }); assert.equal(f.state.emails.length, 0);
    await f.run('send', { id: row.id }); await f.run('send', { id: row.id }); await f.prepare();
    assert.equal(f.state.emails.length, 1);
    assert.match(f.state.emails[0].text, /https:\/\/play.google.com\/apps\/internaltest\/4701051442738255142/);
    assert.equal((await f.service.list()).invitations[0].emailStatus, 'sent');
  });
  await t.test('two concurrent sends have one notification and retain durable state', async t => {
    const f = await fixture(t); const row = await f.prepare(); await f.run('confirm', { id: row.id, confirm: true });
    let release; f.state.pause = new Promise(resolve => { release = resolve; });
    const first = f.run('send', { id: row.id });
    while (!f.state.emails.length) await new Promise(resolve => setTimeout(resolve, 5));
    await assert.rejects(f.run('send', { id: row.id }), { code: 'invitation_in_progress' });
    release(); await first; assert.equal(f.state.emails.length, 1);
  });
  await t.test('failed delivery retains identity, eligibility and idempotency across restart', async t => {
    const f = await fixture(t); const row = await f.prepare(); await f.run('confirm', { id: row.id, confirm: true });
    f.state.failMail = true; const failure = await f.run('send', { id: row.id });
    assert.equal(failure.invitation.emailStatus, 'failed'); assert.equal(failure.invitation.access, 'active'); assert.equal(failure.invitation.playEligibility, 'confirmed');
    assert.doesNotMatch(JSON.stringify(failure), /PRIVATE_PROVIDER_FIXTURE/);
    await assert.rejects(f.run('retry', { id: row.id }), { code: 'invitation_cooldown' });
    f.advance(); f.state.failMail = false;
    await createAndroidTesterService(f.options).run({ action: 'retry', platform: 'android', id: row.id }, 'local-qa-admin');
    assert.equal(f.state.emails[0].idempotencyKey, f.state.emails[1].idempotencyKey);
    assert.deepEqual(f.state.emails[0].text, f.state.emails[1].text);
    assert.equal((await f.pool.query('select count(*) from partner_people')).rows[0].count, '1');
  });
  await t.test('explicit resend has five-minute cooldown and a fresh delivery key only after success', async t => {
    const f = await fixture(t); const row = await f.prepare(); await f.run('confirm', { id: row.id, confirm: true }); await f.run('send', { id: row.id });
    await assert.rejects(f.run('resend', { id: row.id }), { code: 'invitation_cooldown' });
    f.advance(); await f.run('resend', { id: row.id });
    assert.notEqual(f.state.emails[0].idempotencyKey, f.state.emails[1].idempotencyKey);
    assert.equal((await f.prepare()).id, row.id);
  });
  await t.test('uncertain delivery past safe provider deduplication window never sends again', async t => {
    const f = await fixture(t); const row = await f.prepare(); await f.run('confirm', { id: row.id, confirm: true });
    f.state.failMail = true; await f.run('send', { id: row.id }); f.advance(23 * 3600000);
    await assert.rejects(f.run('retry', { id: row.id }), { code: 'mail_delivery_check_required' }); assert.equal(f.state.emails.length, 1);
  });
  await t.test('revocation consumes OTPs, blocks current sessions and leaves Play eligibility intact', async t => {
    const f = await fixture(t); const row = await f.prepare(); await f.run('confirm', { id: row.id, confirm: true });
    await f.access.requestCode({ email: row.email, platform: 'android', ip: '192.0.2.1' });
    const code = f.state.challenges[0].code;
    const verified = await f.access.verifyCode({ email: row.email, code, platform: 'android', ip: '192.0.2.1' });
    const claims = await f.claims(verified.token); assert.equal((await f.access.status(claims)).access, 'active');
    f.advance(60001); await f.access.requestCode({ email: row.email, platform: 'android', ip: '192.0.2.1' });
    const revoked = await f.run('revoke', { id: row.id });
    assert.equal(revoked.invitation.access, 'revoked'); assert.equal(revoked.invitation.playEligibility, 'confirmed');
    assert.equal((await f.access.status(claims)).access, 'revoked');
    assert.equal((await f.pool.query('select count(*) from partner_verifications where consumed_at is null')).rows[0].count, '0');
    await assert.rejects(f.run('send', { id: row.id }), { code: 'preview_access_inactive' });
    await assert.rejects(f.prepare(), { code: 'preview_access_inactive' });
  });
  await t.test('manual Play removal does not revoke access; disable does not remove eligibility', async t => {
    const f = await fixture(t); const row = await f.prepare(); await f.run('confirm', { id: row.id, confirm: true });
    let result = await f.run('removed', { id: row.id, confirm: true });
    assert.equal(result.invitation.access, 'active'); assert.equal(result.invitation.playEligibility, 'removed');
    await assert.rejects(f.run('send', { id: row.id }), { code: 'play_eligibility_unconfirmed' });
    await f.run('confirm', { id: row.id, confirm: true }); result = await f.run('disable', { id: row.id });
    assert.equal(result.invitation.access, 'revoked'); assert.equal(result.invitation.playEligibility, 'confirmed');
  });
  await t.test('new actions audit safe state; no email payload/OTP/token in dashboard projection', async t => {
    const f = await fixture(t); const row = await f.prepare(); await f.run('confirm', { id: row.id, confirm: true }); await f.run('send', { id: row.id });
    const audits = (await f.pool.query("select metadata from partner_access_audit where event='android_tester_invitation'")).rows;
    assert.deepEqual(audits.map(x => x.metadata.action), ['prepare', 'confirm', 'send']);
    const publicState = JSON.stringify(await f.service.list()); assert.doesNotMatch(publicState, /email_payload|code_digest|email_key|idempotencyKey|local-android-tester-fixture/);
  });
  await t.test('untrusted platform/features/org cannot expand provisioning permissions', async t => {
    const f = await fixture(t);
    await assert.rejects(f.service.run({ action: 'prepare', platform: 'ios', email: 'qa@heyzippi.test' }, 'qa'), { code: 'invalid_android_action' });
    const result = await f.run('prepare', { email: 'qa@heyzippi.test', features: { checkout: true }, organizationId: 'untrusted', durationDays: 999 });
    const person = (await f.pool.query('select * from partner_people')).rows[0];
    assert.deepEqual(person.platforms, ['android']); assert.equal(person.features.checkout, false);
    assert.equal(+new Date(person.expires_at) - +new Date(person.starts_at), 7 * 86400000);
    assert.equal(result.invitation.authority, 'production');
  });
});

test('Production OTP contract', async t => {
  await t.test('random six digits, keyed storage, one-time verification and correct Android claims', async t => {
    const f = await fixture(t); const row = await f.prepare(); const request = { email: row.email, platform: 'android', ip: '192.0.2.2' };
    const response = await f.access.requestCode(request);
    assert.equal(response.codeExpiresInSeconds, 600); assert.equal(response.resendAfterSeconds, 60);
    const code = f.state.challenges[0].code; assert.match(code, /^\d{6}$/);
    const stored = (await f.pool.query('select * from partner_verifications')).rows[0];
    assert.equal(stored.code_digest.length, 64); assert.equal(Object.hasOwn(stored, 'code'), false);
    assert.equal(+new Date(stored.expires_at) - +new Date(stored.created_at), 600000);
    await f.access.requestCode(request); assert.equal(f.state.challenges.length, 1);
    const verified = await f.access.verifyCode({ ...request, code }); const claims = await f.claims(verified.token);
    assert.equal(claims.auth_method, 'partner_preview'); assert.equal(claims.platform, 'android'); assert.equal(claims.sub, `partner:${claims.partner_invite_id}`);
    assert.equal(verified.partnerAccess.refreshAfterSeconds, 60);
    await assert.rejects(f.access.verifyCode({ ...request, code }), { code: 'invalid_code' });
  });
  await t.test('OTP expires exactly at ten minutes', async t => {
    const f = await fixture(t); const row = await f.prepare(); const request = { email: row.email, platform: 'android', ip: '192.0.2.3' };
    await f.access.requestCode(request); f.advance(600000);
    await assert.rejects(f.access.verifyCode({ ...request, code: f.state.challenges[0].code }), { code: 'invalid_code' });
  });
  await t.test('five invalid attempts exhaust the challenge', async t => {
    const f = await fixture(t); const row = await f.prepare(); const request = { email: row.email, platform: 'android', ip: '192.0.2.4' };
    await f.access.requestCode(request); const code = f.state.challenges[0].code; const wrong = code === '000000' ? '000001' : '000000';
    for (let i = 0; i < 5; i++) await assert.rejects(f.access.verifyCode({ ...request, code: wrong }), { code: 'invalid_code' });
    await assert.rejects(f.access.verifyCode({ ...request, code }), { code: 'invalid_code' });
    assert.equal((await f.pool.query('select attempts from partner_verifications')).rows[0].attempts, 5);
  });
  await t.test('fresh OTP after sixty seconds consumes the previous challenge', async t => {
    const f = await fixture(t); const row = await f.prepare(); const request = { email: row.email, platform: 'android', ip: '192.0.2.5' };
    await f.access.requestCode(request); f.advance(59999); await f.access.requestCode(request); assert.equal(f.state.challenges.length, 1);
    f.advance(1); await f.access.requestCode(request); assert.equal(f.state.challenges.length, 2);
    assert.equal((await f.pool.query('select count(*) from partner_verifications where consumed_at is null')).rows[0].count, '1');
  });
  await t.test('unapproved address returns neutral response without email or challenge', async t => {
    const f = await fixture(t); const result = await f.access.requestCode({ email: 'unknown@heyzippi.test', platform: 'android', ip: '192.0.2.6' });
    assert.equal(result.ok, true); assert.equal(f.state.challenges.length, 0);
  });
  await t.test('ordinary guest, Google and Apple sessions bypass preview enforcement; revoked preview does not', async () => {
    let checks = 0; const gate = createPartnerAccessEnforcement({ required: false, service: { async status() { checks++; return { access: 'revoked', features: {} }; } } });
    for (const claims of [undefined, { sub: 'google-fixture' }, { sub: 'apple-fixture' }]) {
      let next = false; await gate({ path: '/v1/flights/search', headers: {}, authClaims: claims, userIdVerified: !!claims }, {}, () => { next = true; }); assert.equal(next, true);
    }
    let status; await gate({ path: '/v1/flights/search', headers: {}, authClaims: { sub: 'partner:fixture', auth_method: 'partner_preview' } },
      { status(value) { status = value; return this; }, json() {} }, () => assert.fail('revoked preview admitted'));
    assert.equal(checks, 1); assert.equal(status, 403);
  });
});
