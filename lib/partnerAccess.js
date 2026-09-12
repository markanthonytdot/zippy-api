const crypto = require("node:crypto");
const { validAccessDuration, MAX_ACCESS_DURATION_DAYS } = require("./partnerAccessDuration");
// Recognize and reject reviewer-prefixed records unless an explicit adapter is supplied.
// Production does not ship or instantiate the staging reviewer override.
const REVIEW_DIGEST_PREFIX = "review:v1:";

const CODE_TTL_SECONDS = 600;
const RESEND_SECONDS = 60;
const ATTEMPT_LIMIT = 5;
const DEFAULT_FEATURES = Object.freeze({ flights: true, hotels: true, combinedTrip: true, checkout: false });
const EMPTY_FEATURES = Object.freeze({ flights: false, hotels: false, combinedTrip: false, checkout: false });
const REQUEST_RESPONSE = Object.freeze({ ok: true, message: "If this email is approved, a verification code will arrive shortly.", resendAfterSeconds: RESEND_SECONDS, codeExpiresInSeconds: CODE_TTL_SECONDS });

class PartnerAccessError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
function normalizeEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  // Do not rewrite plus tags/dots or assume mailbox equivalence. ASCII work email v1.
  if (email.length > 254 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$/.test(email)) throw new PartnerAccessError(400, "invalid_email");
  return email;
}
function normalizePlatform(value) {
  if (!["ios", "android"].includes(value)) throw new PartnerAccessError(400, "invalid_platform");
  return value;
}
function normalizePlatforms(value) {
  if (!Array.isArray(value) || !value.length) throw new PartnerAccessError(400, "invalid_platforms");
  return [...new Set(value.map(normalizePlatform))];
}
function normalizeFeatures(value, fallback = DEFAULT_FEATURES) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new PartnerAccessError(400, "invalid_features");
  const result = { ...fallback };
  for (const [key, enabled] of Object.entries(value)) {
    if (!/^[a-z][A-Za-z0-9_]{0,63}$/.test(key) || ["__proto__", "constructor", "prototype"].includes(key) || typeof enabled !== "boolean") throw new PartnerAccessError(400, "invalid_features");
    result[key] = enabled;
  }
  return result;
}
function iso(value) { return value == null ? null : new Date(value).toISOString(); }
function accessState(person, platform, now = Date.now()) {
  if (!person) return "unavailable";
  if (person.revoked_at || person.status !== "active" || person.organization_status !== "active") return "revoked";
  if (platform && !person.platforms.includes(platform)) return "unavailable";
  if (new Date(person.starts_at).getTime() > now) return "scheduled";
  if (new Date(person.expires_at).getTime() <= now) return "expired";
  return "active";
}
function projectStatus(person, platform, now = Date.now()) {
  const access = accessState(person, platform, now);
  return {
    ok: true, access, organization: person?.organization || null,
    startsAt: iso(person?.starts_at), expiresAt: iso(person?.expires_at), serverTime: iso(now),
    refreshAfterSeconds: 60, platforms: person?.platforms || [],
    features: access === "active" ? { ...EMPTY_FEATURES, ...person.features } : { ...EMPTY_FEATURES },
  };
}
function projectPerson(person, now) {
  return {
    id: person.id, email: person.email, organizationId: person.organization_id, organization: person.organization,
    status: person.status, access: person.status === "disabled" || person.organization_status === "disabled" ? "disabled" : accessState(person, null, now),
    startsAt: iso(person.starts_at), expiresAt: iso(person.expires_at), revokedAt: iso(person.revoked_at),
    activatedAt: iso(person.activated_at), lastCheckedAt: iso(person.last_checked_at), lastActiveAt: iso(person.last_active_at),
    platforms: person.platforms, features: person.features, createdAt: iso(person.created_at), updatedAt: iso(person.updated_at),
  };
}
function projectOrganization(row) {
  return { id: row.id, name: row.name, status: row.status, allowedEmailDomains: row.allowed_email_domains, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at) };
}
function codeDigest(secret, id, code) { return crypto.createHmac("sha256", secret).update(`partner-code:v1:${id}:${code}`).digest("hex"); }
function equalDigest(a, b) {
  const left = Buffer.from(String(a), "hex"); const right = Buffer.from(String(b), "hex");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
const PERSON_SELECT = `select p.*, o.name as organization, o.status as organization_status, o.allowed_email_domains
  from partner_people p join partner_organizations o on o.id=p.organization_id`;

function createDevelopmentMailAdapter({ enabled = false, production = false, fixedCode } = {}) {
  if (!enabled || production) return { configured: false, async send() { throw new PartnerAccessError(503, "mail_unavailable"); } };
  if (fixedCode && !/^\d{6}$/.test(fixedCode)) throw new Error("Development verification code must contain six digits.");
  // This is the recipient's simulated mailbox, not the verification database or logs.
  const mailbox = new Map();
  return { configured: true, development: true, fixedCode,
    async send(message) {
      if (!message.email.endsWith(".test")) throw new PartnerAccessError(503, "development_email_required");
      mailbox.set(message.email, { ...message });
    },
    read(email) { return mailbox.get(normalizeEmail(email)) || null; },
  };
}

function createPartnerAccessService({ dbPool, secret, signToken, mailAdapter, reviewerAccess = null, now = Date.now } = {}) {
  const mail = mailAdapter || createDevelopmentMailAdapter();
  function requireReady() {
    if (!dbPool || !secret || !signToken) throw new PartnerAccessError(503, "partner_access_unavailable");
  }
  async function transaction(work, existingClient = null) {
    requireReady();
    const client = existingClient || await dbPool.connect();
    try {
      await client.query("begin");
      const result = await work(client);
      await client.query("commit");
      return result;
    } catch (error) { await client.query("rollback"); throw error; }
    finally { if (!existingClient) client.release(); }
  }
  async function audit(client, person, event, actor, metadata = {}) {
    await client.query(`insert into partner_access_audit(person_id,organization_id,event,actor,metadata,created_at) values($1,$2,$3,$4,$5,$6)`,
      [person?.id || null, person?.organization_id || null, event, String(actor).slice(0, 120), metadata, iso(now())]);
  }
  async function lockEmail(client, email) {
    await client.query("select pg_advisory_xact_lock(hashtextextended($1, 0))", [`partner-email:${email}`]);
  }
  async function personByEmail(client, email) { return (await client.query(`${PERSON_SELECT} where p.email=$1 for update of p`, [email])).rows[0]; }
  async function personById(client, id, lock = false) {
    if (!/^[0-9a-f-]{36}$/i.test(String(id))) return null;
    return (await client.query(`${PERSON_SELECT} where p.id=$1${lock ? " for update of p" : ""}`, [id])).rows[0];
  }
  async function rateLimit(input, action) {
    requireReady();
    const stamp = now();
    const rules = [["email", input.email, action === "request" ? 5 : 20, 3600], ["ip", input.ip || "unknown", action === "request" ? 20 : 60, 600]];
    if (input.deviceId) rules.push(["device", String(input.deviceId).slice(0, 200), action === "request" ? 10 : 30, 600]);
    let allowed = true;
    for (const [kind, value, limit, seconds] of rules) {
      const key = crypto.createHmac("sha256", secret).update(`${action}:${kind}:${value}`).digest("hex");
      const row = (await dbPool.query(`insert into partner_access_rate_limits(bucket_key,count,expires_at) values($1,1,$2)
        on conflict(bucket_key) do update set count=case when partner_access_rate_limits.expires_at <= $3 then 1 else partner_access_rate_limits.count+1 end,
        expires_at=case when partner_access_rate_limits.expires_at <= $3 then excluded.expires_at else partner_access_rate_limits.expires_at end returning count`,
      [key, iso(stamp + seconds * 1000), iso(stamp)])).rows[0];
      if (row.count > limit) allowed = false;
    }
    // Bound retained operational identifiers; does not remove live rate-limit windows.
    await dbPool.query("delete from partner_access_rate_limits where expires_at < $1", [iso(stamp - 86400000)]);
    if (!allowed) throw new PartnerAccessError(429, "rate_limited");
  }
  async function requestCode(input) {
    const email = normalizeEmail(input.email); const platform = normalizePlatform(input.platform);
    await rateLimit({ ...input, email }, "request");
    if (!mail.configured) throw new PartnerAccessError(503, "mail_unavailable");
    await transaction(async client => {
      await lockEmail(client, email);
      const person = await personByEmail(client, email);
      if (!person || !["active", "scheduled"].includes(accessState(person, platform, now()))) return;
      if (person.allowed_email_domains.length && !person.allowed_email_domains.includes(email.split("@")[1])) return;
      const latest = (await client.query("select * from partner_verifications where person_id=$1 order by created_at desc limit 1", [person.id])).rows[0];
      if (latest && now() - new Date(latest.created_at).getTime() < RESEND_SECONDS * 1000) return;
      const review = reviewerAccess?.challenge(email, platform, person.expires_at, now());
      const id = crypto.randomUUID(); const code = review ? review.code : mail.development && mail.fixedCode ? mail.fixedCode : String(crypto.randomInt(0, 1000000)).padStart(6, "0");
      await client.query("update partner_verifications set consumed_at=$2 where person_id=$1 and consumed_at is null", [person.id, iso(now())]);
      await client.query(`insert into partner_verifications(id,person_id,code_digest,platform,expires_at,created_at) values($1,$2,$3,$4,$5,$6)`,
        [id, person.id, (review ? REVIEW_DIGEST_PREFIX : "") + codeDigest(secret, id, code), platform, iso(review ? review.expiresAt : now() + CODE_TTL_SECONDS * 1000), iso(now())]);
      try { if (!review) await mail.send({ email, code, expiresInSeconds: CODE_TTL_SECONDS }); }
      catch {
        await client.query("update partner_verifications set consumed_at=$2 where id=$1", [id, iso(now())]);
        await audit(client, person, "code_delivery_failed", "system", { platform });
        return;
      }
      await audit(client, person, "code_requested", "partner", { platform });
      await client.query("delete from partner_verifications where expires_at < $1", [iso(now() - 86400000)]);
    });
    return { ...REQUEST_RESPONSE };
  }
  async function verifyCode(input) {
    const email = normalizeEmail(input.email); const platform = normalizePlatform(input.platform);
    await rateLimit({ ...input, email }, "verify");
    const result = await transaction(async client => {
      await lockEmail(client, email);
      const person = await personByEmail(client, email);
      if (!person || !["active", "scheduled"].includes(accessState(person, platform, now()))) return null;
      if (person.allowed_email_domains.length && !person.allowed_email_domains.includes(email.split("@")[1])) return null;
      const verification = (await client.query("select * from partner_verifications where person_id=$1 order by created_at desc limit 1 for update", [person.id])).rows[0];
      if (!verification || verification.consumed_at || verification.platform !== platform || verification.attempts >= ATTEMPT_LIMIT || new Date(verification.expires_at).getTime() <= now()) return null;
      await client.query("update partner_verifications set attempts=attempts+1 where id=$1", [verification.id]);
      const isReview = verification.code_digest.startsWith(REVIEW_DIGEST_PREFIX);
      const review = isReview && reviewerAccess?.challenge(email, platform, person.expires_at, now());
      if (isReview && (!review || !equalDigest(verification.code_digest.slice(REVIEW_DIGEST_PREFIX.length), codeDigest(secret, verification.id, review.code)))) return null;
      const expected = isReview ? verification.code_digest.slice(REVIEW_DIGEST_PREFIX.length) : verification.code_digest;
      if (!/^\d{6}$/.test(String(input.code)) || !equalDigest(expected, codeDigest(secret, verification.id, String(input.code)))) return null;
      await client.query("update partner_verifications set consumed_at=$2 where id=$1", [verification.id, iso(now())]);
      await client.query("update partner_people set activated_at=coalesce(activated_at,$2),last_active_at=$2 where id=$1", [person.id, iso(now())]);
      const subject = `partner:${person.id}`;
      const token = await signToken(subject, { auth_method: "partner_preview", partner_invite_id: person.id, platform });
      if (!token) throw new PartnerAccessError(503, "partner_access_unavailable");
      await audit(client, person, "verified", "partner", { platform, appVersion: String(input.appVersion || "").slice(0, 40) });
      return { ok: true, token, user: { sub: subject, authMethod: "partner_preview" }, partnerAccess: projectStatus(person, platform, now()) };
    });
    if (!result) throw new PartnerAccessError(401, "invalid_code");
    return result;
  }
  async function status(claims) {
    if (claims?.auth_method !== "partner_preview") return { ...projectStatus(null, null, now()), access: "none" };
    if (!claims.partner_invite_id || claims.sub !== `partner:${claims.partner_invite_id}` || !["ios", "android"].includes(claims.platform)) throw new PartnerAccessError(401, "invalid_auth");
    return transaction(async client => {
      const person = await personById(client, claims.partner_invite_id, true);
      const projection = projectStatus(person, claims.platform, now());
      if (person) {
        await client.query(`update partner_people set last_checked_at=$2,last_active_at=case when $3 then $2 else last_active_at end where id=$1`, [person.id, iso(now()), projection.access === "active"]);
        if (projection.access === "expired" && !person.expiry_audited_at) {
          await audit(client, person, "expired", "system");
          await client.query("update partner_people set expiry_audited_at=$2 where id=$1", [person.id, iso(now())]);
        }
      }
      return projection;
    });
  }
  async function list() {
    requireReady();
    const [organizations, people] = await Promise.all([dbPool.query("select * from partner_organizations order by name"), dbPool.query(`${PERSON_SELECT} order by p.created_at desc limit 1000`)]);
    return { ok: true, serverTime: iso(now()), organizations: organizations.rows.map(projectOrganization), people: people.rows.map(row => projectPerson(row, now())) };
  }
  async function createOrganization(input, actor) {
    const name = String(input.name || "").trim();
    if (!name || name.length > 160) throw new PartnerAccessError(400, "invalid_organization");
    if (input.allowedEmailDomains != null && !Array.isArray(input.allowedEmailDomains)) throw new PartnerAccessError(400, "invalid_domains");
    const domains = [...new Set((input.allowedEmailDomains || []).map(value => normalizeEmail(`preview@${String(value).trim().toLowerCase()}`).split("@")[1]))];
    return transaction(async client => {
      const row = (await client.query("insert into partner_organizations(id,name,allowed_email_domains,created_at,updated_at) values($1,$2,$3,$4,$4) returning *", [crypto.randomUUID(), name, JSON.stringify(domains), iso(now())])).rows[0];
      await audit(client, { organization_id: row.id }, "organization_created", actor);
      return { ok: true, organization: projectOrganization(row) };
    });
  }
  function expiry(input, start) {
    // Never let an alternate timestamp conceal an invalid duration or an unbounded expiry.
    if (input.durationDays !== undefined && (!validAccessDuration(input.durationDays) || input.expiresAt != null))
      throw new PartnerAccessError(400, "invalid_duration");
    const end = input.expiresAt != null ? new Date(input.expiresAt).getTime() : validAccessDuration(input.durationDays) ? start + input.durationDays * 86400000 : NaN;
    if (end - start > MAX_ACCESS_DURATION_DAYS * 86400000) throw new PartnerAccessError(400, "invalid_expiry");
    if (!Number.isFinite(end) || end <= start) throw new PartnerAccessError(400, "invalid_expiry");
    return iso(end);
  }
  async function createPerson(input, actor) {
    const email = normalizeEmail(input.email); const start = input.startsAt ? new Date(input.startsAt).getTime() : now();
    if (!Number.isFinite(start)) throw new PartnerAccessError(400, "invalid_start");
    const end = expiry(input, start); const platforms = normalizePlatforms(input.platforms || ["ios", "android"]); const features = normalizeFeatures(input.features || {});
    return transaction(async client => {
      await lockEmail(client, email);
      if (await personByEmail(client, email)) throw new PartnerAccessError(409, "email_already_invited");
      if (!/^[0-9a-f-]{36}$/i.test(String(input.organizationId))) throw new PartnerAccessError(400, "invalid_organization");
      const organization = (await client.query("select * from partner_organizations where id=$1", [input.organizationId])).rows[0];
      if (!organization || organization.status !== "active") throw new PartnerAccessError(400, "invalid_organization");
      if (organization.allowed_email_domains.length && !organization.allowed_email_domains.includes(email.split("@")[1])) throw new PartnerAccessError(400, "email_domain_not_allowed");
      const id = crypto.randomUUID();
      await client.query(`insert into partner_people(id,email,organization_id,starts_at,expires_at,platforms,features,created_at,updated_at) values($1,$2,$3,$4,$5,$6,$7,$8,$8)`, [id, email, organization.id, iso(start), end, JSON.stringify(platforms), features, iso(now())]);
      const person = await personById(client, id);
      await audit(client, person, "invitation_created", actor, { expiresAt: end, platforms, features });
      return { ok: true, person: projectPerson(person, now()) };
    });
  }
  async function changePerson(id, action, input, actor) {
    return transaction(async client => {
      const person = await personById(client, id, true);
      if (!person) throw new PartnerAccessError(404, "person_not_found");
      if (action === "extend") {
        if (input.expectedExpiresAt !== undefined && input.expectedExpiresAt !== iso(person.expires_at))
          throw new PartnerAccessError(409, "expiry_changed");
        const end = expiry(input, input.expiresAt ? Math.max(now(), new Date(person.starts_at).getTime()) : Math.max(now(), new Date(person.expires_at).getTime()));
        if (new Date(end).getTime() <= new Date(person.expires_at).getTime()) throw new PartnerAccessError(400, "extension_must_increase_expiry");
        await client.query("update partner_people set expires_at=$2,expiry_audited_at=null,updated_at=$3 where id=$1", [id, end, iso(now())]);
        await audit(client, person, "access_extended", actor, { previousExpiresAt: iso(person.expires_at), expiresAt: end });
      } else if (action === "revoke") {
        await client.query("update partner_people set revoked_at=$2,updated_at=$2 where id=$1", [id, iso(now())]);
        await client.query("update partner_verifications set consumed_at=$2 where person_id=$1 and consumed_at is null", [id, iso(now())]);
        await audit(client, person, "access_revoked", actor);
      } else if (action === "update") {
        const features = input.features ? normalizeFeatures(input.features, person.features) : person.features;
        const platforms = input.platforms ? normalizePlatforms(input.platforms) : person.platforms;
        if (input.status != null && !["active", "disabled"].includes(input.status)) throw new PartnerAccessError(400, "invalid_status");
        await client.query("update partner_people set features=$2,platforms=$3,status=$4,revoked_at=$5,updated_at=$6 where id=$1", [id, features, JSON.stringify(platforms), input.status || person.status, input.status === "active" ? null : person.revoked_at, iso(now())]);
        await audit(client, person, "entitlement_updated", actor, { features, platforms, status: input.status || person.status });
      } else throw new PartnerAccessError(400, "invalid_action");
      return { ok: true, person: projectPerson(await personById(client, id), now()) };
    });
  }
  // The invitation dashboard shares the same identity, locks and entitlement policy as OTP access.
  // It may add a platform; it must never silently restore, extend or broaden feature permissions.
  async function ensureTesterAccess({ email: rawEmail, platform: rawPlatform, organizationId, selectedOrganizationId = null, durationDays = 7 }, actor, existingClient = null) {
    const email = normalizeEmail(rawEmail); const platform = normalizePlatform(rawPlatform);
    if (!validAccessDuration(durationDays)) throw new PartnerAccessError(400, "invalid_duration");
    return transaction(async client => {
      await lockEmail(client, email);
      let person = await personByEmail(client, email);
      if (selectedOrganizationId) {
        if (!/^[0-9a-f-]{36}$/i.test(String(selectedOrganizationId))) throw new PartnerAccessError(400, "invalid_organization");
        const selected = (await client.query("select * from partner_organizations where id=$1", [selectedOrganizationId])).rows[0];
        if (!selected || selected.status !== "active") throw new PartnerAccessError(400, "invalid_organization");
        if (selected.allowed_email_domains.length && !selected.allowed_email_domains.includes(email.split("@")[1])) throw new PartnerAccessError(400, "email_domain_not_allowed");
      }
      if (person) {
        if (accessState(person, null, now()) !== "active") throw new PartnerAccessError(409, "preview_access_inactive");
        if (selectedOrganizationId && person.organization_id !== selectedOrganizationId) {
          const previousOrganizationId = person.organization_id;
          await client.query("update partner_people set organization_id=$2,updated_at=$3 where id=$1", [person.id, selectedOrganizationId, iso(now())]);
          person = await personById(client, person.id);
          await audit(client, person, "tester_organization_selected", actor, { previousOrganizationId });
        }
        if (!person.platforms.includes(platform)) {
          const platforms = [...person.platforms, platform];
          await client.query("update partner_people set platforms=$2,updated_at=$3 where id=$1", [person.id, JSON.stringify(platforms), iso(now())]);
          await audit(client, person, "tester_platform_authorized", actor, { platform });
          person = await personById(client, person.id);
        }
      } else {
        organizationId = selectedOrganizationId || organizationId;
        if (!/^[0-9a-f-]{36}$/i.test(String(organizationId))) throw new PartnerAccessError(503, "tester_policy_not_configured");
        const org = (await client.query("select * from partner_organizations where id=$1", [organizationId])).rows[0];
        if (!org || org.status !== "active") throw new PartnerAccessError(503, "tester_policy_not_configured");
        if (org.allowed_email_domains.length && !org.allowed_email_domains.includes(email.split("@")[1])) throw new PartnerAccessError(400, "email_domain_not_allowed");
        const start = now(); const end = expiry({ durationDays }, start);
        const id = crypto.randomUUID();
        await client.query(`insert into partner_people(id,email,organization_id,starts_at,expires_at,platforms,features,created_at,updated_at)
          values($1,$2,$3,$4,$5,$6,$7,$4,$4)`, [id, email, org.id, iso(start), end, JSON.stringify([platform]), DEFAULT_FEATURES]);
        person = await personById(client, id);
        await audit(client, person, "invitation_created", actor, { expiresAt: end, platforms: [platform], features: DEFAULT_FEATURES });
      }
      return projectPerson(person, now());
    }, existingClient);
  }
  async function deletionTarget(client, person) {
    const rows = (await client.query("select platform from tester_invitations where person_id=$1", [person.id])).rows;
    return { personId: person.id, email: person.email, organizationId: person.organization_id,
      platforms: [...new Set([...person.platforms, ...rows.map(row => row.platform)])].sort(), scope: "entire_partner_person" };
  }
  async function describeDeletion(id) {
    requireReady();
    const person = await personById(dbPool, id);
    if (!person) throw new PartnerAccessError(404, "person_not_found");
    return { ok: true, target: await deletionTarget(dbPool, person) };
  }
  async function deletePerson(id, input, actor) {
    if (!actor) throw new PartnerAccessError(401, "admin_auth_required");
    if (input.confirm !== true || input.scope !== "entire_partner_person" || input.personId !== id)
      throw new PartnerAccessError(400, "delete_confirmation_required");
    const email = normalizeEmail(input.email);
    await rateLimit({ email: actor, ip: "admin-delete" }, "admin-delete");
    return transaction(async client => {
      // Same lock order as invitations: delivery lock, email lock, person row.
      const locked = (await client.query("select pg_try_advisory_xact_lock(hashtextextended($1,0)) as acquired", [`tester-invite:${email}`])).rows[0].acquired;
      if (!locked) throw new PartnerAccessError(409, "invitation_in_progress");
      await lockEmail(client, email);
      const person = await personById(client, id, true);
      if (!person) throw new PartnerAccessError(404, "person_not_found");
      const target = await deletionTarget(client, person);
      if (person.email !== email || input.organizationId !== target.organizationId ||
          !Array.isArray(input.platforms) || JSON.stringify([...input.platforms].sort()) !== JSON.stringify(target.platforms))
        throw new PartnerAccessError(409, "delete_target_changed");
      // Retain one minimal security event, not old invitation/delivery history.
      await client.query("delete from partner_access_audit where person_id=$1", [id]);
      await audit(client, person, "person_deleted", actor, { personId: id, platforms: target.platforms,
        scope: target.scope, result: "deleted", externalTestersChanged: false });
      await client.query("delete from partner_people where id=$1", [id]);
      return { ok: true, deleted: true, personId: id, externalTestersChanged: false };
    });
  }
  async function deleteAccount(claims) {
    if (claims?.auth_method !== "partner_preview") return;
    if (claims.sub !== `partner:${claims.partner_invite_id}`) throw new PartnerAccessError(401, "invalid_auth");
    await transaction(async client => {
      const person = await personById(client, claims.partner_invite_id, true);
      if (!person) return;
      await audit(client, person, "account_deleted", "partner");
      await client.query("delete from partner_people where id=$1", [person.id]);
    });
  }
  return { requestCode, verifyCode, status, list, createOrganization, createPerson, changePerson, ensureTesterAccess, describeDeletion, deletePerson, deleteAccount };
}

module.exports = { PartnerAccessError, normalizeEmail, normalizeFeatures, normalizePlatforms, accessState, projectStatus, codeDigest, createDevelopmentMailAdapter, createPartnerAccessService };
