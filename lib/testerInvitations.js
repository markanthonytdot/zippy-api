const crypto = require("node:crypto");
const { PartnerAccessError, normalizeEmail, accessState } = require("./partnerAccess");
const { invitationInstructions } = require("./testerInvitationEmail");
const { APPLE_STATES, APPLE_INVITED_STATES } = require("./testerInvitationProviders");

const SAFE_ERRORS = new Set(["apple_not_configured", "apple_authorization_failed", "apple_rate_limited", "apple_unavailable",
  "apple_invalid_response", "apple_result_limit", "apple_group_mismatch", "apple_no_testable_build", "apple_tester_ambiguous",
  "apple_invitation_pending", "apple_membership_unconfirmed", "apple_tester_revoked", "android_preview_build_unverified", "platform_unavailable",
  "mail_unavailable", "mail_delivery_check_required", "preview_access_inactive", "invitation_cooldown", "android_production_authority_required"]);
const { safeAppleMetadata } = require("./appleInvitationDiagnostics");
const COOLDOWN_MS = 300000;
const CONFIRMATION_INTERVAL_MS = 60000;
const MAX_CONFIRMATION_CHECKS = 20;
// Temporary, non-configurable recipient scope; never a general invitation bypass.
const QA_EMAIL = "s.mark@mac.com";
const QA_GROUP = "39a3f713-9168-4e9a-abc4-2d97f7cf7cdb";
const SELECT = `select i.*,p.email,p.organization_id,p.status,p.revoked_at,p.platforms,p.starts_at,p.expires_at,
  o.name as organization, o.status as organization_status from tester_invitations i join partner_people p on p.id=i.person_id
  join partner_organizations o on o.id=p.organization_id`;
function safeError(error, fallback = "platform_unavailable") { return SAFE_ERRORS.has(error?.code) ? error.code : fallback; }
function project(row, now) {
  return { id: row.id, email: row.email, organizationId: row.organization_id, organization: row.organization,
    platform: row.platform, access: accessState(row, row.platform, now),
    expiresAt: row.expires_at, platformStatus: row.platform_status, providerState: row.provider_state,
    emailStatus: row.email_status, invitedAt: row.platform_confirmed_at, emailSentAt: row.email_sent_at,
    createdAt: row.created_at, updatedAt: row.updated_at, lastAttemptAt: row.last_attempt_at, error: row.error_code,
    confirmationPending: !!row.confirmation_pending_since, nextConfirmationCheckAt: row.confirmation_next_check_at,
    retryAfter: row.last_attempt_at ? new Date(new Date(row.last_attempt_at).getTime() + COOLDOWN_MS).toISOString() : null };
}
function createTesterInvitationService({ dbPool, partnerAccessService, providers, mailAdapter, secret, env = process.env, now = Date.now }) {
  const organizationId = env.ZIPPI_TESTER_ORGANIZATION_ID;
  const durationDays = Number(env.ZIPPI_TESTER_DURATION_DAYS || 7);
  const policyConfigured = /^[0-9a-f-]{36}$/i.test(String(organizationId || "")) && [3, 7, 14].includes(durationDays);
  const emailConfigured = !!(mailAdapter?.configured && mailAdapter.sendInstructions);
  const enabled = env.ZIPPI_TESTER_INVITES_ENABLED === "true";
  const qaConfigured = env.ZIPPI_TESTER_QA_ENABLED === "true"
    && env.RENDER_SERVICE_ID === "srv-dagq12ht0dsc73a7dm40"
    && env.ZIPPI_TESTER_APPLE_APP_ID === "6757395108"
    && !!providers.iosQA?.configured;
  const reconciliationContext = Object.freeze({});
  const qaAllowed = context => qaConfigured && (context?.authenticatedAdmin === true || context === reconciliationContext);
  function ready(context) {
    if (!dbPool || !secret || (!enabled && !qaAllowed(context))) throw new PartnerAccessError(503, "tester_invitations_disabled");
  }
  async function list(context) {
    const qa = qaAllowed(context) ? { email: QA_EMAIL, platform: "ios" } : null;
    const qaOnly = !enabled ? qa : null;
    const config = { enabled, policyConfigured, durationDays: policyConfigured ? durationDays : null, emailConfigured,
      qa, qaOnly, platforms: { ios: !!(qaOnly ? providers.iosQA : providers.ios)?.configured, android: !qaOnly && !!providers.android?.configured } };
    if ((!enabled && !qaOnly) || !dbPool) return { ok: true, config, invitations: [] };
    const rows = (await dbPool.query(`${SELECT}${qaOnly ? " where p.email=$1 and i.platform='ios'" : ""} order by i.updated_at desc limit 200`,
      qaOnly ? [QA_EMAIL] : [])).rows;
    const organizations = (await dbPool.query("select id,name from partner_organizations where status='active' order by name,id")).rows;
    return { ok: true, config, organizations, invitations: rows.map(row => project(row, now())) };
  }
  async function audit(client, row, actor, action, result) {
    await client.query(`insert into partner_access_audit(person_id,organization_id,event,actor,metadata,created_at) values($1,$2,'tester_invitation',$3,$4,$5)`,
      [row.person_id, row.organization_id, String(actor).slice(0, 120), { invitationId: row.id, platform: row.platform, action, result }, new Date(now())]);
  }
  async function rateLimit(actor) {
    for (const [value, limit] of [[String(actor), 30], ["global", 150]]) {
      const key = crypto.createHmac("sha256", secret).update(`tester-invite:${value}`).digest("hex");
      const row = (await dbPool.query(`insert into partner_access_rate_limits(bucket_key,count,expires_at) values($1,1,$2)
        on conflict(bucket_key) do update set count=case when partner_access_rate_limits.expires_at <= $3 then 1 else partner_access_rate_limits.count+1 end,
        expires_at=case when partner_access_rate_limits.expires_at <= $3 then excluded.expires_at else partner_access_rate_limits.expires_at end returning count`,
      [key, new Date(now() + 3600000), new Date(now())])).rows[0];
      if (row.count > limit) throw new PartnerAccessError(429, "rate_limited");
    }
  }
  async function run(input, actor, action = "invite", context) {
    ready(context);
    if (!["invite", "retry", "resend", "apple-resend", "refresh"].includes(action) && !(action === "reconcile" && context === reconciliationContext)) throw new PartnerAccessError(400, "invalid_action");
    let email, platform;
    if (action === "invite") {
      email = normalizeEmail(input.email); platform = input.platform;
      if (!["ios", "android"].includes(platform)) throw new PartnerAccessError(400, "invalid_platform");
      if (!policyConfigured) throw new PartnerAccessError(503, "tester_policy_not_configured");
    } else {
      if (!/^[0-9a-f-]{36}$/i.test(String(input.id))) throw new PartnerAccessError(404, "invitation_not_found");
      const row = (await dbPool.query(`${SELECT} where i.id=$1`, [input.id])).rows[0];
      if (!row) throw new PartnerAccessError(404, "invitation_not_found");
      ({ email, platform } = row);
    }
    if (env.ZIPPI_ANDROID_TESTER_REMOTE_ENABLED === "true" && platform === "android") throw new PartnerAccessError(409, "android_production_authority_required");
    // Resolve stored identity for every row action before allowing any side effect.
    const isQA = email === QA_EMAIL;
    if (isQA ? (!qaAllowed(context) || platform !== "ios") : !enabled) throw new PartnerAccessError(403, "tester_qa_restricted");
    const provider = isQA ? providers.iosQA : providers[platform];
    if (!provider?.configured) throw new PartnerAccessError(503, platform === "android" ? "android_preview_build_unverified" : "apple_not_configured");
    const selectedOrganizationId = action === "invite" && input.organizationId ? input.organizationId : null;
    if (selectedOrganizationId && !/^[0-9a-f-]{36}$/i.test(String(selectedOrganizationId))) throw new PartnerAccessError(400, "invalid_organization");
    const automatic = action === "reconcile";
    if (!automatic) await rateLimit(actor);
    const client = await dbPool.connect();
    const lockKey = `tester-invite:${email}`;
    let locked = false;
    try {
      locked = (await client.query("select pg_try_advisory_lock(hashtextextended($1,0)) as acquired", [lockKey])).rows[0].acquired;
      if (!locked) throw new PartnerAccessError(409, "invitation_in_progress");
      // A queued retry must not recreate an identity deleted after its initial lookup.
      if (action !== "invite" && !(await client.query("select id from tester_invitations where id=$1", [input.id])).rows.length)
        throw new PartnerAccessError(404, "invitation_not_found");
      // Only the new-person form may provision access. Row actions never recreate or alter it.
      const person = action === "invite" ? await partnerAccessService.ensureTesterAccess({ email, platform, organizationId, selectedOrganizationId, durationDays }, actor, client) : null;
      if (action === "invite") await client.query(`insert into tester_invitations(id,person_id,platform,created_at,updated_at) values($1,$2,$3,$4,$4) on conflict(person_id,platform) do nothing`,
        [crypto.randomUUID(), person.id, platform, new Date(now())]);
      let row;
      async function read() {
        row = (await client.query(`${SELECT} where ${person ? "i.person_id=$1 and i.platform=$2" : "i.id=$1"}`, person ? [person.id, platform] : [input.id])).rows[0];
        if (!row) throw new PartnerAccessError(404, "invitation_not_found");
        return row;
      }
      async function update(fields) {
        const names = Object.keys(fields); // All fields originate from fixed server code below.
        await client.query(`update tester_invitations set ${names.map((name, i) => `${name}=$${i + 2}`).join(",")},updated_at=$${names.length + 2} where id=$1`,
          [row.id, ...names.map(name => name === "provider_metadata" ? JSON.stringify(fields[name]) : fields[name]), new Date(now())]);
        await read();
      }
      async function requireActive() {
        await read();
        if (accessState(row, platform, now()) !== "active") throw new PartnerAccessError(409, "preview_access_inactive");
      }
      async function reserveNotification() {
        if (row.apple_resend_at && now() - new Date(row.apple_resend_at).getTime() < COOLDOWN_MS) throw new PartnerAccessError(429, "invitation_cooldown");
        await update({ apple_resend_at: new Date(now()) });
      }
      await read();
      // Repeated Invite is a read of the same durable workflow, never a hidden resend/retry.
      if (action === "invite" && row.last_attempt_at) return { ok: !row.error_code, invitation: project(row, now()) };
      if (automatic && (!row.confirmation_next_check_at || new Date(row.confirmation_next_check_at).getTime() > now() || row.confirmation_checks >= MAX_CONFIRMATION_CHECKS)) return { ok: true, invitation: project(row, now()) };
      if (!automatic && row.last_attempt_at && now() - new Date(row.last_attempt_at).getTime() < COOLDOWN_MS) throw new PartnerAccessError(429, "invitation_cooldown");
      if (automatic && accessState(row, platform, now()) !== 'active') {
        await update({ confirmation_next_check_at: null });
        return { ok: false, invitation: project(row, now()) };
      }
      const wasPending = !!row.confirmation_pending_since;
      const priorMetadata = safeAppleMetadata(row.provider_metadata);
      const checks = automatic ? row.confirmation_checks + 1 : 0;
      await update({ last_attempt_at: new Date(now()), error_code: null, confirmation_checks: checks,
        ...(automatic ? { confirmation_next_check_at: checks < MAX_CONFIRMATION_CHECKS ? new Date(now() + CONFIRMATION_INTERVAL_MS) : null } : {}) });
      async function checkpoint(reference) {
        const fields = { provider_metadata: safeAppleMetadata([...priorMetadata, ...safeAppleMetadata(reference.metadata)]) };
        if (/^[A-Za-z0-9-]{1,80}$/.test(String(reference.testerId || ''))) fields.provider_tester_id = reference.testerId;
        if (APPLE_STATES.has(reference.state)) fields.provider_state = reference.state;
        if (reference.pending) Object.assign(fields, { platform_status: 'pending',
          confirmation_pending_since: row.confirmation_pending_since || new Date(now()),
          confirmation_next_check_at: checks < MAX_CONFIRMATION_CHECKS ? new Date(now() + CONFIRMATION_INTERVAL_MS) : null });
        await update(fields);
      }
      async function confirm() {
        const options = { reserveNotification, checkpoint };
        let result;
        if (wasPending) result = await provider.reconcile(email, row.provider_tester_id, options);
        else result = await provider.enroll(email, options);
        if (platform === 'ios') await checkpoint({ ...result, pending: result.state === 'NOT_INVITED' });
        if (platform === 'ios' && result.state === 'NOT_INVITED') throw new PartnerAccessError(503, 'apple_invitation_pending');
        if (!(platform === 'ios' ? APPLE_INVITED_STATES.has(result.state) : result.state === 'OPT_IN_REQUIRED')) throw new Error('Invalid provider state');
        await update({ platform_status: 'confirmed', provider_state: result.state, provider_tester_id: result.testerId || null,
          platform_confirmed_at: row.platform_confirmed_at || new Date(now()), confirmation_pending_since: null });
      }
      try {
        if ((action === "refresh" || action === "apple-resend") && !wasPending) {
          if (platform !== "ios" || !row.provider_tester_id || row.platform_status !== "confirmed") throw new PartnerAccessError(409, "apple_membership_unconfirmed");
          const result = action === "refresh" ? await provider.refresh(row.provider_tester_id)
            : await provider.resend(row.provider_tester_id, { reserveNotification, checkpoint });
          if (!APPLE_STATES.has(result.state)) throw new Error("Invalid provider state");
          await update({ provider_state: result.state, platform_status: 'confirmed', confirmation_pending_since: null, confirmation_next_check_at: null,
            ...(result.metadata ? { provider_metadata: safeAppleMetadata([...priorMetadata, ...result.metadata]) } : {}) });
        } else {
          // Any action on a pending record is read-only reconciliation, never a resend.
          if (wasPending || row.platform_status !== "confirmed" || (platform === "ios" && row.provider_state === "NOT_INVITED")) await confirm();
          await requireActive();
          if (row.provider_state === "REVOKED") throw new PartnerAccessError(409, "apple_tester_revoked");
          if (row.email_status !== "sent" || action === "resend") {
            try {
              if (!emailConfigured) throw new PartnerAccessError(503, "mail_unavailable");
              if (row.email_key && row.email_status !== "sent" && now() - new Date(row.email_started_at).getTime() >= 23 * 3600000) {
                throw new PartnerAccessError(409, "mail_delivery_check_required");
              }
              if (!row.email_key || row.email_status === "sent") await update({ email_key: crypto.randomUUID(), email_started_at: new Date(now()), email_payload: invitationInstructions(platform, row.email) });
              await update({ email_status: "sending" });
              const sent = await mailAdapter.sendInstructions({ email, ...row.email_payload, idempotencyKey: `zippi-tester-${row.email_key}` });
              await update({ email_status: "sent", email_sent_at: new Date(now()), email_message_id: sent?.id || null, confirmation_next_check_at: null });
            } catch (error) {
              await update({ email_status: "failed", error_code: safeError(error, "mail_unavailable") });
              throw error;
            }
          }
          await update({ confirmation_next_check_at: null });
        }
      } catch (error) {
        if (error.providerReference) await checkpoint(error.providerReference);
        const pending = platform === 'ios' && (error.code === 'apple_invitation_pending' || error.confirmationUncertain);
        if (pending) await update({ platform_status: 'pending', error_code: 'apple_invitation_pending',
          confirmation_pending_since: row.confirmation_pending_since || new Date(now()),
          confirmation_next_check_at: checks < MAX_CONFIRMATION_CHECKS ? new Date(now() + CONFIRMATION_INTERVAL_MS) : null });
        else await update({ error_code: row.error_code || safeError(error), confirmation_next_check_at: null,
          // A definite refusal stays a hard failure. A previously pending write remains
          // protected from notification retries even if a later status GET is refused.
          ...(row.platform_status !== 'confirmed' ? { platform_status: 'failed', confirmation_pending_since: wasPending ? row.confirmation_pending_since : null } : {}) });
      }
      await audit(client, row, actor, action, row.error_code || "accepted");
      return { ok: !row.error_code, invitation: project(row, now()) };
    } finally {
      let discard = false;
      if (locked) {
        try { await client.query("select pg_advisory_unlock(hashtextextended($1,0))", [lockKey]); }
        catch { discard = true; }
      }
      client.release(discard);
    }
  }
  let reconciling = false;
  async function reconcilePending() {
    if (reconciling || !dbPool || !secret || (!enabled && !qaConfigured)) return;
    reconciling = true;
    try {
      const rows = (await dbPool.query(`${SELECT} where i.platform='ios' and i.confirmation_next_check_at <= $1
        and i.confirmation_checks < $2 order by i.confirmation_next_check_at limit 10`, [new Date(now()), MAX_CONFIRMATION_CHECKS])).rows;
      for (const row of rows) {
        if (row.email === QA_EMAIL ? !qaConfigured : !enabled) continue;
        try { await run({ id: row.id }, 'invitation-confirmation-worker', 'reconcile', reconciliationContext); }
        catch { /* Durable row/lock governs retries. Never log provider errors or recipient data. */ }
      }
    } finally { reconciling = false; }
  }
  return { list, run, reconcilePending };
}
module.exports = { createTesterInvitationService, SAFE_ERRORS, QA_GROUP };
