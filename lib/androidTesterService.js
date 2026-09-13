const crypto = require('node:crypto');
const { ACCESS_DURATION_DAYS, validAccessDuration } = require('./partnerAccessDuration');
const { PartnerAccessError, normalizeEmail, accessState } = require('./partnerAccess');
const { androidTesterEmail, ANDROID_TEST_URL } = require('./androidTesterEmail');
const DEFAULT_ORGANIZATION = 'd64dfe7a-3058-4e43-9283-182f60b08baa';
const COOLDOWN_MS = 300000;
const ACTIONS = new Set(['prepare', 'confirm', 'unconfirm', 'removed', 'send', 'retry', 'resend', 'revoke', 'disable', 'extend', 'adjust']);
const SELECT = `select i.*, p.email, p.organization_id, p.status, p.revoked_at, p.platforms,
  p.starts_at, p.expires_at, p.features, o.status as organization_status
  from tester_invitations i join partner_people p on p.id=i.person_id
  join partner_organizations o on o.id=p.organization_id`;
function project(row, now) {
  return { id: row.id, email: row.email, platform: 'android', authority: 'production',
    access: row.status === 'disabled' || row.organization_status === 'disabled' ? 'disabled' : accessState(row, 'android', now), expiresAt: new Date(row.expires_at).toISOString(),
    playEligibility: row.play_eligibility, playEligibilityAt: row.play_eligibility_at,
    emailStatus: row.email_status, emailSentAt: row.email_sent_at, error: row.error_code,
    retryAfter: row.last_attempt_at ? new Date(+new Date(row.last_attempt_at) + COOLDOWN_MS).toISOString() : null };
}
function createAndroidTesterService({ dbPool, access, mail, secret, enabled = false,
  organizationId = DEFAULT_ORGANIZATION, durationDays = 7, now = Date.now }) {
  const policy = /^[0-9a-f-]{36}$/i.test(organizationId) && validAccessDuration(durationDays);
  function ready() { if (!enabled || !dbPool || !secret || !policy) throw new PartnerAccessError(503, 'android_testers_unavailable'); }
  async function list() {
    const config = { enabled: !!enabled, policyConfigured: policy, emailConfigured: !!mail?.configured,
      authority: 'production', durationDays, durationOptions: ACCESS_DURATION_DAYS, durationMinDays: 1, durationMaxDays: 90, testingUrl: ANDROID_TEST_URL };
    if (!enabled) return { ok: true, config, invitations: [] };
    ready();
    const rows = (await dbPool.query(`${SELECT} where i.platform='android' order by i.updated_at desc limit 200`)).rows;
    return { ok: true, config, invitations: rows.map(row => project(row, now())) };
  }
  async function rateLimit(actor) {
    for (const [identity, limit] of [[actor, 30], ['global', 150]]) {
      const key = crypto.createHmac('sha256', secret).update(`android-tester-admin:${identity}`).digest('hex');
      const stamp = new Date(now());
      const row = (await dbPool.query(`insert into partner_access_rate_limits(bucket_key,count,expires_at) values($1,1,$2)
        on conflict(bucket_key) do update set count=case when partner_access_rate_limits.expires_at <= $3 then 1 else partner_access_rate_limits.count+1 end,
        expires_at=case when partner_access_rate_limits.expires_at <= $3 then excluded.expires_at else partner_access_rate_limits.expires_at end returning count`,
      [key, new Date(now() + 3600000), stamp])).rows[0];
      if (row.count > limit) throw new PartnerAccessError(429, 'rate_limited');
    }
  }
  async function run(input, actor) {
    ready();
    if (!actor) throw new PartnerAccessError(401, 'admin_auth_required');
    if (input.platform !== 'android' || !ACTIONS.has(input.action)) throw new PartnerAccessError(400, 'invalid_android_action');
    const action = input.action;
    const selectedDays = input.durationDays === undefined && action !== 'adjust' ? durationDays : input.durationDays;
    if (['prepare', 'extend', 'adjust'].includes(action) && !validAccessDuration(selectedDays))
      throw new PartnerAccessError(400, 'invalid_duration');
    if (['extend', 'adjust'].includes(action) && (input.confirm !== true || typeof input.expectedExpiresAt !== 'string'))
      throw new PartnerAccessError(400, 'manual_confirmation_required');
    if (action === 'adjust' && !['set', 'extend'].includes(input.operation)) throw new PartnerAccessError(400, 'invalid_adjustment');
    let email;
    if (action === 'prepare') email = normalizeEmail(input.email);
    else {
      if (!/^[0-9a-f-]{36}$/i.test(input.id || '')) throw new PartnerAccessError(404, 'invitation_not_found');
      const found = (await dbPool.query(`${SELECT} where i.id=$1 and i.platform='android'`, [input.id])).rows[0];
      if (!found) throw new PartnerAccessError(404, 'invitation_not_found');
      email = found.email;
    }
    await rateLimit(actor);
    const client = await dbPool.connect(); const lock = `tester-invite:${email}`;
    let locked = false; let row;
    try {
      locked = (await client.query('select pg_try_advisory_lock(hashtextextended($1,0)) as acquired', [lock])).rows[0].acquired;
      if (!locked) throw new PartnerAccessError(409, 'invitation_in_progress');
      let person;
      if (action === 'prepare') {
        person = await access.ensureTesterAccess({ email, platform: 'android', organizationId, durationDays: selectedDays }, actor, client);
        await client.query(`insert into tester_invitations(id,person_id,platform,created_at,updated_at) values($1,$2,'android',$3,$3)
          on conflict(person_id,platform) do nothing`, [crypto.randomUUID(), person.id, new Date(now())]);
      }
      async function read() {
        row = (await client.query(`${SELECT} where i.platform='android' and ${person ? 'i.person_id=$1' : 'i.id=$1'}`, [person?.id || input.id])).rows[0];
        if (!row) throw new PartnerAccessError(404, 'invitation_not_found');
      }
      async function update(fields) {
        const names = Object.keys(fields); // Fixed fields supplied by this service only.
        await client.query(`update tester_invitations set ${names.map((k, i) => `${k}=$${i + 2}`).join(',')},updated_at=$${names.length + 2} where id=$1`,
          [row.id, ...Object.values(fields), new Date(now())]);
        await read();
      }
      async function audit(result) {
        await client.query(`insert into partner_access_audit(person_id,organization_id,event,actor,metadata,created_at) values($1,$2,'android_tester_invitation',$3,$4,$5)`,
          [row.person_id, row.organization_id, String(actor).slice(0,120), { action, result, invitationId: row.id, platform: 'android', authority: 'production' }, new Date(now())]);
      }
      await read();
      if (['confirm', 'unconfirm', 'removed'].includes(action)) {
        if (input.confirm !== true) throw new PartnerAccessError(400, 'manual_confirmation_required');
        if (action === 'confirm' && accessState(row, 'android', now()) !== 'active') throw new PartnerAccessError(409, 'preview_access_inactive');
        const value = { confirm: 'confirmed', unconfirm: 'not_confirmed', removed: 'removed' }[action];
        await update({ play_eligibility: value, play_eligibility_at: new Date(now()), play_eligibility_actor: String(actor).slice(0,120) });
      } else if (['extend', 'adjust'].includes(action)) {
        // Dedicated, audited action; stale submissions cannot overwrite a newer expiry.
        await access.changePerson(row.person_id, action, { durationDays: selectedDays,
          expectedExpiresAt: input.expectedExpiresAt, operation: input.operation, confirm: input.confirm }, actor);
        await read(); // Adjustment never restores blocked access or changes Play/email state.
      } else if (action === 'revoke' || action === 'disable') {
        await access.changePerson(row.person_id, action === 'disable' ? 'update' : 'revoke', action === 'disable' ? { status: 'disabled' } : {}, actor);
        await read(); // Play eligibility remains independent and untouched.
      } else if (['send', 'retry', 'resend'].includes(action)) {
        if (accessState(row, 'android', now()) !== 'active') throw new PartnerAccessError(409, 'preview_access_inactive');
        if (row.play_eligibility !== 'confirmed') throw new PartnerAccessError(409, 'play_eligibility_unconfirmed');
        if (row.email_status === 'sent' && action !== 'resend') return { ok: true, invitation: project(row, now()) };
        if (row.last_attempt_at && now() - +new Date(row.last_attempt_at) < COOLDOWN_MS) throw new PartnerAccessError(429, 'invitation_cooldown');
        if (!mail?.configured) throw new PartnerAccessError(503, 'mail_unavailable');
        if (row.email_key && row.email_status !== 'sent' && now() - +new Date(row.email_started_at) >= 23 * 3600000)
          throw new PartnerAccessError(409, 'mail_delivery_check_required');
        if (!row.email_key || row.email_status === 'sent') await update({ email_key: crypto.randomUUID(), email_started_at: new Date(now()), email_payload: androidTesterEmail(email) });
        await update({ last_attempt_at: new Date(now()), email_status: 'sending', error_code: null });
        try {
          const sent = await mail.sendInstructions({ email, ...row.email_payload, idempotencyKey: `zippi-android-tester-${row.email_key}` });
          if (!sent?.id) throw new Error('mail_unconfirmed');
          await update({ email_status: 'sent', email_sent_at: new Date(now()), email_message_id: sent.id });
        } catch {
          await update({ email_status: 'failed', error_code: 'mail_unavailable' });
        }
      }
      await audit(row.error_code || 'accepted');
      return { ok: !row.error_code, invitation: project(row, now()) };
    } finally {
      let discard = false;
      if (locked) try { await client.query('select pg_advisory_unlock(hashtextextended($1,0))', [lock]); } catch { discard = true; }
      client.release(discard);
    }
  }
  return { list, run };
}
module.exports = { createAndroidTesterService, DEFAULT_ORGANIZATION, ACTIONS };
