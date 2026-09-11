const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { createPartnerAccessService, PartnerAccessError } = require("../lib/partnerAccess");
const { createTesterInvitationService } = require("../lib/testerInvitations");
const { createTesterInvitationRouter } = require("../lib/testerInvitationRoutes");
const qaContext = { authenticatedAdmin: true };
const qaEnv = { ZIPPI_TESTER_INVITES_ENABLED: "false", ZIPPI_TESTER_QA_ENABLED: "true",
  RENDER_SERVICE_ID: "srv-dagq12ht0dsc73a7dm40", ZIPPI_TESTER_APPLE_APP_ID: "6757395108",
  ZIPPI_TESTER_APPLE_GROUP_ID: "39a3f713-9168-4e9a-abc4-2d97f7cf7cdb" };

test("QA gate fails closed without its flag, exact staging service, app, separate provider or trusted admin context", async () => {
  for (const patch of [{ ZIPPI_TESTER_QA_ENABLED: "false" }, { RENDER_SERVICE_ID: "production" },
    { ZIPPI_TESTER_APPLE_APP_ID: "other-app" }]) {
    const service = createTesterInvitationService({ dbPool: { query() { assert.fail("No database access expected"); } },
      secret: "test-only", providers: { iosQA: { configured: true } }, env: { ...qaEnv, ...patch } });
    await assert.rejects(service.run({ email: "s.mark@mac.com", platform: "ios" }, "admin", "invite", qaContext),
      error => error.code === "tester_invitations_disabled");
    assert.equal((await service.list(qaContext)).config.qaOnly, null);
  }
  const service = createTesterInvitationService({ dbPool: {}, secret: "test-only", providers: {}, env: qaEnv });
  for (const context of [undefined, {}, { authenticatedAdmin: false }]) {
    await assert.rejects(service.run({ email: "s.mark@mac.com", platform: "ios", authenticatedAdmin: true }, "admin", "invite", context),
      error => error.code === "tester_invitations_disabled");
    assert.equal((await service.list(context)).config.qaOnly, null);
  }
});

test("admin invitation routes pass trusted context separately from untrusted request fields", async () => {
  const calls = [];
  const router = createTesterInvitationRouter({ service: { run: async (...args) => { calls.push(args); return { ok: true }; } } });
  for (const layer of router.stack.filter(layer => layer.route?.methods.post)) {
    await layer.route.stack[0].handle({ body: { email: "s.mark@mac.com", platform: "ios", authenticatedAdmin: false },
      params: { id: "invitation-fixture" }, zippiAdmin: { actor: "verified-admin" } }, { json() {} });
  }
  assert.equal(calls.length, 5);
  for (const [input, actor, , context] of calls) {
    assert.equal(actor, "verified-admin"); assert.deepEqual(context, qaContext);
    assert.equal(Object.hasOwn(input, "authenticatedAdmin"), false);
  }
});

test("invitation router rejects unauthenticated, foreign-origin and non-JSON requests", () => {
  const guard = createTesterInvitationRouter({ service: {} }).stack[0].handle;
  for (const [admin, origin, json, expected] of [[null, "https://admin.test", true, 401], [{}, "https://evil.test", true, 403], [{}, "https://admin.test", false, 403], [{}, "https://admin.test", true, 200]]) {
    let status = 200, next = false;
    guard({ zippiAdmin: admin, method: "POST", protocol: "https", get: key => key === "host" ? "admin.test" : origin, is: () => json },
      { setHeader() {}, status(code) { status = code; return this; }, json() {} }, () => { next = true; });
    assert.equal(status, expected); assert.equal(next, expected === 200);
  }
});
test("invitation routes never return unexpected provider exception content", async () => {
  const router = createTesterInvitationRouter({ service: { list: async () => { throw new Error("private-key-fixture"); } } });
  const route = router.stack.find(layer => layer.route?.path === "/").route.stack[0].handle;
  let body;
  await route({}, { status() { return this; }, json(value) { body = value; } });
  assert.deepEqual(body, { ok: false, error: "tester_invitations_unavailable" });
});
const databaseUrl = process.env.PARTNER_TEST_DATABASE_URL;
test("durable tester invitations with isolated PostgreSQL and mocked external delivery", { skip: !databaseUrl }, async t => {
  assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(new URL(databaseUrl).hostname));
  const schema = `tester_invites_${crypto.randomBytes(8).toString("hex")}`;
  const setup = new Pool({ connectionString: databaseUrl, ssl: false }); await setup.query(`create schema ${schema}`);
  const pool = new Pool({ connectionString: databaseUrl, ssl: false, options: `-c search_path=${schema}` });
  t.after(async () => { await pool.end(); await setup.query(`drop schema ${schema} cascade`); await setup.end(); });
  for (const file of ["013_partner_access.sql", "014_tester_invitations.sql"]) await pool.query(fs.readFileSync(path.join(__dirname, "../migrations", file), "utf8"));
  let clock = Date.parse("2026-09-10T12:00:00Z"), serial = 0;
  const access = createPartnerAccessService({ dbPool: pool, secret: "local-test-only", signToken() {}, now: () => clock });
  const org = (await access.createOrganization({ name: "Fixture Testers", allowedEmailDomains: ["example.test"] }, "test-admin")).organization;
  function fixture() {
    serial++; const email = `person${serial}@example.test`, actor = `admin${serial}`;
    const calls = { ios: [], android: [], email: [], resend: 0 };
    let failPlatform = false, failMail = false, pause;
    const provider = platform => ({ configured: true, async enroll(address) {
      calls[platform].push(address); if (pause) await pause;
      if (failPlatform) throw new Error("private-provider-response-fixture");
      return platform === "ios" ? { testerId: "tester-fixture", state: "INVITED" } : { state: "OPT_IN_REQUIRED" };
    }, async refresh() { return { state: "INSTALLED" }; }, async resend(_id, { reserveNotification }) { await reserveNotification(); calls.resend++; return { state: "INVITED" }; } });
    const providers = { ios: provider("ios"), iosQA: provider("ios"), android: provider("android") };
    const mailAdapter = { configured: true, async sendInstructions(message) { calls.email.push(message); if (failMail) throw new Error("mail-secret-fixture"); return { id: "message-fixture" }; } };
    const env = { ZIPPI_TESTER_INVITES_ENABLED: "true", ZIPPI_TESTER_ORGANIZATION_ID: org.id, RESEND_API_KEY: "secret-fixture-not-returned" };
    const service = createTesterInvitationService({ dbPool: pool, partnerAccessService: access, providers, mailAdapter, secret: "local-test-only", env, now: () => clock });
    return { email, actor, service, calls, providers, env, mailAdapter,
      invite: (platform = "ios") => service.run({ email, platform }, actor),
      action: (id, action) => service.run({ id }, actor, action),
      set failPlatform(value) { failPlatform = value; }, set failMail(value) { failMail = value; }, set pause(value) { pause = value; } };
  }
  function advance() { clock += 300001; }
  await t.test("selected organization is used for new identities and survives retries without duplicates", async () => {
    const f = fixture();
    const selected = (await access.createOrganization({ name: "Test Organization", allowedEmailDomains: ["example.test"] }, f.actor)).organization;
    f.failPlatform = true;
    const first = await f.service.run({ email: f.email, platform: "ios", organizationId: selected.id }, f.actor);
    assert.equal(first.invitation.organizationId, selected.id); assert.equal(first.invitation.organization, "Test Organization");
    advance(); f.failPlatform = false;
    const retry = await f.action(first.invitation.id, "retry"); assert.equal(retry.ok, true); assert.equal(retry.invitation.organizationId, selected.id);
    const repeated = await f.service.run({ email: f.email, platform: "ios", organizationId: selected.id }, f.actor);
    assert.equal(repeated.invitation.id, first.invitation.id); assert.equal(f.calls.email.length, 1);
    assert.equal((await pool.query("select count(*)::int n from partner_people where email=$1", [f.email])).rows[0].n, 1);
    assert.equal((await f.service.list()).organizations.filter(x => x.id === selected.id).length, 1);
  });
  await t.test("organization selection validates domains and active records before provider or identity changes", async () => {
    const f = fixture();
    const wrongDomain = (await access.createOrganization({ name: "Restricted", allowedEmailDomains: ["elsewhere.test"] }, f.actor)).organization;
    const inactive = (await access.createOrganization({ name: "Inactive", allowedEmailDomains: [] }, f.actor)).organization;
    await pool.query("update partner_organizations set status='disabled' where id=$1", [inactive.id]);
    for (const [id, code] of [["invalid", "invalid_organization"], [crypto.randomUUID(), "invalid_organization"], [inactive.id, "invalid_organization"], [wrongDomain.id, "email_domain_not_allowed"]]) {
      await assert.rejects(f.service.run({ email: f.email, platform: "ios", organizationId: id }, f.actor), e => e.code === code);
    }
    assert.equal(f.calls.ios.length + f.calls.email.length, 0);
    assert.equal((await pool.query("select count(*)::int n from partner_people where email=$1", [f.email])).rows[0].n, 0);
  });
  await t.test("explicit organization changes preserve existing expiry and custom permissions; omission preserves organization", async () => {
    const f = fixture();const selected = (await access.createOrganization({ name: "Selected", allowedEmailDomains: ["example.test"] }, f.actor)).organization;
    const old = (await access.createPerson({ email: f.email, organizationId: org.id, durationDays: 3, platforms: ["ios"], features: { flights: false, combinedTrip: false } }, f.actor)).person;
    const first = await f.invite(); assert.equal(first.invitation.organizationId, org.id);
    const changed = await f.service.run({ email: f.email, platform: "ios", organizationId: selected.id }, f.actor);
    assert.equal(changed.invitation.organizationId, selected.id);assert.equal(changed.invitation.expiresAt.toISOString(), old.expiresAt);
    const person = (await pool.query("select * from partner_people where email=$1", [f.email])).rows[0];
    assert.equal(person.id, old.id);assert.equal(person.features.flights, false);assert.equal(person.features.combinedTrip, false);
    assert.equal((await f.invite()).invitation.organizationId, selected.id);assert.equal(f.calls.email.length, 1);
  });
  await t.test("general partner mode never routes the designated QA account into the partner provider; disabled Android cannot mutate access", async () => {
    const f = fixture();let qaCalls = 0;
    const service = createTesterInvitationService({ dbPool: pool, partnerAccessService: access, secret: "test-only", now: () => clock,
      env: { ...qaEnv, ZIPPI_TESTER_INVITES_ENABLED: "true", ZIPPI_TESTER_ORGANIZATION_ID: org.id, ZIPPI_TESTER_APPLE_GROUP_ID: "partners-group" },
      mailAdapter: f.mailAdapter, providers: { ios: f.providers.ios, android: { configured: false }, iosQA: { configured: true, async enroll() { qaCalls++;return { testerId: "qa-tester", state: "INVITED" }; } } } });
    await assert.rejects(service.run({ email: f.email, platform: "android" }, f.actor, "invite", qaContext), e => e.code === "android_preview_build_unverified");
    await assert.rejects(service.run({ email: "s.mark@mac.com", platform: "ios" }, f.actor), e => e.code === "tester_qa_restricted");
    await service.run({ email: f.email, platform: "ios" }, f.actor, "invite", qaContext);
    assert.equal(qaCalls, 0); assert.equal(f.calls.ios.length, 1);
    const listed = await service.list(qaContext);assert.equal(listed.config.enabled, true);assert.equal(listed.config.qaOnly, null);assert.equal(listed.config.qa.email, "s.mark@mac.com");
  });
  await t.test("QA-only invitations reuse one-day access and remain idempotent; all other identities and platforms are blocked", async () => {
    const f = fixture();
    const qaOrg = (await access.createOrganization({ name: "Isolated QA", allowedEmailDomains: ["mac.com"] }, f.actor)).organization;
    const person = (await access.createPerson({ email: "s.mark@mac.com", organizationId: qaOrg.id,
      expiresAt: new Date(clock + 86400000).toISOString(), platforms: ["ios"],
      features: { flights: true, hotels: true, combinedTrip: true, checkout: false } }, f.actor)).person;
    const service = createTesterInvitationService({ dbPool: pool, partnerAccessService: access, providers: f.providers,
      mailAdapter: f.mailAdapter, secret: "test-only", env: { ...qaEnv, ZIPPI_TESTER_ORGANIZATION_ID: qaOrg.id }, now: () => clock });
    for (const [email, platform] of [["someone@mac.com", "ios"], ["s.mark+qa@mac.com", "ios"], ["s.mark@me.com", "ios"], ["s.mark@mac.com", "android"]]) {
      await assert.rejects(service.run({ email, platform }, f.actor, "invite", qaContext), error => error.code === "tester_qa_restricted");
    }
    assert.equal(f.calls.ios.length + f.calls.android.length + f.calls.email.length, 0);
    const first = await service.run({ email: "s.mark@mac.com", platform: "ios" }, f.actor, "invite", qaContext);
    assert.equal(first.ok, true); assert.equal(first.invitation.access, "active");
    const again = await service.run({ email: "s.mark@mac.com", platform: "ios" }, f.actor, "invite", qaContext);
    assert.equal(again.invitation.id, first.invitation.id); assert.equal(f.calls.ios.length, 1); assert.equal(f.calls.email.length, 1);
    const retained = (await pool.query("select * from partner_people where email=$1", ["s.mark@mac.com"])).rows;
    assert.equal(retained.length, 1); assert.equal(retained[0].id, person.id);
    assert.equal(retained[0].expires_at.toISOString(), person.expiresAt); assert.equal(retained[0].features.checkout, false);
    const unrelated = await f.invite();
    const android = await f.invite("android");
    for (const id of [unrelated.invitation.id, android.invitation.id]) {
      for (const action of ["retry", "resend", "apple-resend", "refresh"]) {
        await assert.rejects(service.run({ id }, f.actor, action, qaContext), error => error.code === "tester_qa_restricted");
      }
    }
    const listed = await service.list(qaContext);
    assert.equal(listed.config.enabled, false); assert.deepEqual(listed.config.qaOnly, { email: "s.mark@mac.com", platform: "ios" });
    assert.equal(listed.config.platforms.android, false); assert.deepEqual(listed.invitations.map(x => x.id), [first.invitation.id]);
    advance(); await service.run({ id: first.invitation.id }, f.actor, "apple-resend", qaContext);
    assert.equal(f.calls.resend, 1);
    await assert.rejects(service.run({ id: first.invitation.id }, f.actor, "resend", qaContext), error => error.code === "invitation_cooldown");
    const generalService = createTesterInvitationService({ dbPool: pool, partnerAccessService: access,
      providers: { ...f.providers, ios: { configured: true, async refresh() { assert.fail("QA must never use the partner group"); } } },
      mailAdapter: f.mailAdapter, secret: "test-only", env: { ...qaEnv, ZIPPI_TESTER_INVITES_ENABLED: "true", ZIPPI_TESTER_APPLE_GROUP_ID: "partners-group", ZIPPI_TESTER_ORGANIZATION_ID: qaOrg.id }, now: () => clock });
    advance();
    const refreshed = await generalService.run({ id: first.invitation.id }, f.actor, "refresh", qaContext);
    assert.equal(refreshed.invitation.providerState, "INSTALLED");
    await access.changePerson(person.id, "revoke", {}, f.actor); advance();
    await assert.rejects(service.run({ email: "s.mark@mac.com", platform: "ios" }, f.actor, "invite", qaContext), error => error.code === "preview_access_inactive");
  });
  for (const platform of ["ios", "android"]) {
    await t.test(`new ${platform} tester: access, platform and welcome in order`, async () => {
      const f = fixture(); const result = await f.invite(platform);
      assert.equal(result.ok, true); assert.equal(result.invitation.access, "active"); assert.equal(result.invitation.platformStatus, "confirmed"); assert.equal(result.invitation.emailStatus, "sent");
      assert.equal(result.invitation.providerState, platform === "ios" ? "INVITED" : "OPT_IN_REQUIRED");
      assert.equal(f.calls[platform].length, 1); assert.equal(f.calls.email.length, 1);
      const person = (await pool.query("select * from partner_people where email=$1", [f.email])).rows[0];
      assert.deepEqual(person.platforms, [platform]); assert.deepEqual(person.features, { flights: true, hotels: true, combinedTrip: true, checkout: false });
      assert.equal(new Date(person.expires_at) - new Date(person.starts_at), 7 * 86400000);
    });
    await t.test(`existing ${platform} tester: repeated invite is idempotent and sends no duplicate`, async () => {
      const f = fixture(); const first = await f.invite(platform); advance(); const next = await f.invite(platform);
      assert.equal(first.invitation.id, next.invitation.id); assert.equal(f.calls[platform].length, 1); assert.equal(f.calls.email.length, 1);
      assert.equal((await pool.query("select count(*)::int n from partner_people where email=$1", [f.email])).rows[0].n, 1);
    });
    await t.test(`${platform} provider failure preserves access and sends no welcome; retry recovers`, async () => {
      const f = fixture(); f.failPlatform = true; const result = await f.invite(platform);
      assert.equal(result.ok, false); assert.equal(result.invitation.access, "active"); assert.equal(result.invitation.platformStatus, "failed");
      assert.equal(result.invitation.emailStatus, "not_sent"); assert.equal(f.calls.email.length, 0);
      assert.equal(JSON.stringify(result).includes("private-provider-response-fixture"), false);
      advance(); f.failPlatform = false; const retry = await f.action(result.invitation.id, "retry");
      assert.equal(retry.ok, true); assert.equal(f.calls.email.length, 1);
    });
  }
  await t.test("existing Partner Access reuses identity, expiry and restrictions", async () => {
    const f = fixture(); const old = (await access.createPerson({ email: f.email, organizationId: org.id, durationDays: 3, platforms: ["android"], features: { flights: false, combinedTrip: false } }, f.actor)).person;
    await f.invite();
    const person = (await pool.query("select * from partner_people where email=$1", [f.email])).rows[0];
    assert.equal(person.id, old.id); assert.equal(person.expires_at.toISOString(), old.expiresAt); assert.equal(person.features.flights, false); assert.equal(person.features.combinedTrip, false);
    assert.deepEqual(person.platforms, ["android", "ios"]);
  });
  await t.test("same email on both platforms shares one identity and two workflows", async () => {
    const f = fixture(); const ios = await f.invite(); const android = await f.invite("android");
    assert.notEqual(ios.invitation.id, android.invitation.id);
    const rows = (await pool.query("select * from partner_people where email=$1", [f.email])).rows;
    assert.equal(rows.length, 1); assert.deepEqual(rows[0].platforms, ["ios", "android"]); assert.equal(f.calls.email.length, 2);
  });
  await t.test("normalization reuses exact email without merging plus tags", async () => {
    const f = fixture(); const first = await f.service.run({ email: ` ${f.email.toUpperCase()} `, platform: "ios" }, f.actor);
    assert.equal(first.invitation.email, f.email); assert.equal((await f.invite()).invitation.id, first.invitation.id);
  });
  await t.test("welcome failure never repeats enrollment and retries same Resend key/body", async () => {
    const f = fixture(); f.failMail = true; const first = await f.invite(); assert.equal(first.invitation.error, "mail_unavailable");
    assert.equal(first.invitation.platformStatus, "confirmed"); assert.equal(first.invitation.emailStatus, "failed");
    advance(); f.failMail = false; const result = await f.action(first.invitation.id, "retry");
    assert.equal(result.ok, true); assert.equal(f.calls.ios.length, 1); assert.deepEqual(f.calls.email[0], f.calls.email[1]);
  });
  await t.test("explicit resend uses a fresh key, no platform write, and cooldown prevents spam", async () => {
    const f = fixture(); const first = await f.invite();
    await assert.rejects(f.action(first.invitation.id, "resend"), error => error.code === "invitation_cooldown");
    advance(); await f.action(first.invitation.id, "resend");
    assert.equal(f.calls.ios.length, 1); assert.equal(f.calls.email.length, 2); assert.notEqual(f.calls.email[0].idempotencyKey, f.calls.email[1].idempotencyKey);
  });
  await t.test("uncertain email after idempotency window requires manual check, no duplicate send", async () => {
    const f = fixture(); f.failMail = true; const first = await f.invite(); clock += 24 * 3600000; f.failMail = false;
    const result = await f.action(first.invitation.id, "retry"); assert.equal(result.invitation.error, "mail_delivery_check_required"); assert.equal(f.calls.email.length, 1);
  });
  await t.test("refresh and explicit Apple resend do not send Zippi email or re-enroll", async () => {
    const f = fixture(); const first = await f.invite(); advance(); await f.action(first.invitation.id, "apple-resend");
    assert.equal(f.calls.resend, 1); advance(); const status = await f.action(first.invitation.id, "refresh");
    assert.equal(status.invitation.providerState, "INSTALLED"); assert.equal(f.calls.ios.length, 1); assert.equal(f.calls.email.length, 1);
  });
  await t.test("concurrent same-email invitations use a durable cross-connection lock", async () => {
    const f = fixture(); let release; f.pause = new Promise(resolve => { release = resolve; });
    const first = f.invite();
    while (!f.calls.ios.length) await new Promise(resolve => setTimeout(resolve, 2));
    try { await assert.rejects(f.invite(), error => error.code === "invitation_in_progress"); } finally { release(); }
    const result = await first; assert.equal(result.ok, true); assert.equal(f.calls.email.length, 1);
    assert.equal((await f.invite()).invitation.id, result.invitation.id);
  });
  await t.test("revoked and expired access cannot be silently restored or extended", async () => {
    for (const kind of ["revoked", "expired"]) {
      const f = fixture(); const person = (await access.createPerson({ email: f.email, organizationId: org.id, durationDays: 3 }, f.actor)).person;
      if (kind === "revoked") await access.changePerson(person.id, "revoke", {}, f.actor); else clock += 4 * 86400000;
      await assert.rejects(f.invite(), error => error.code === "preview_access_inactive"); assert.equal(f.calls.ios.length, 0);
    }
  });
  await t.test("revoke while provider is pending prevents welcome email", async () => {
    const f = fixture(); let release; f.pause = new Promise(resolve => { release = resolve; }); const pending = f.invite();
    while (!f.calls.ios.length) await new Promise(resolve => setTimeout(resolve, 2));
    const person = (await pool.query("select id from partner_people where email=$1", [f.email])).rows[0];
    await access.changePerson(person.id, "revoke", {}, f.actor); release();
    const result = await pending; assert.equal(result.invitation.error, "preview_access_inactive"); assert.equal(f.calls.email.length, 0);
  });
  await t.test("malformed email, unsupported platform and disallowed domain never reach providers", async () => {
    const f = fixture();
    await assert.rejects(f.service.run({ email: "bad", platform: "ios" }, f.actor), error => error.code === "invalid_email");
    await assert.rejects(f.invite("both"), error => error.code === "invalid_platform");
    await assert.rejects(f.service.run({ email: "outside@elsewhere.test", platform: "ios" }, f.actor), error => error.code === "email_domain_not_allowed");
    assert.equal(f.calls.ios.length, 0);
  });
  await t.test("admin action rate limit is database-backed", async () => {
    const f = fixture(); await f.invite();
    for (let i = 0; i < 29; i++) await f.invite();
    await assert.rejects(f.invite(), error => error.code === "rate_limited"); assert.equal(f.calls.email.length, 1);
  });
  await t.test("dashboard returns only allowlisted data, never provider IDs, keys or message payload", async () => {
    const f = fixture(); await f.invite(); const reply = JSON.stringify(await f.service.list());
    for (const sensitive of ["secret-fixture-not-returned", "email_key", "email_payload", "email_message_id", "tester-fixture", "private-key", "idempotencyKey"]) assert.equal(reply.includes(sensitive), false, sensitive);
  });
  await t.test("each completed attempt records admin actor, platform, result and timestamp without email duplication", async () => {
    const f = fixture(); const result = await f.invite();
    const row = (await pool.query("select * from partner_access_audit where event='tester_invitation' and metadata->>'invitationId'=$1", [result.invitation.id])).rows[0];
    assert.equal(row.actor, f.actor); assert.equal(row.metadata.platform, "ios"); assert.equal(row.metadata.result, "accepted"); assert.ok(row.created_at); assert.equal(JSON.stringify(row.metadata).includes(f.email), false);
  });
  await t.test("account deletion cascades workflow rows and audit does not retain the email", async () => {
    const f = fixture(); const result = await f.invite(); const person = (await pool.query("select id from partner_people where email=$1", [f.email])).rows[0];
    await access.deleteAccount({ auth_method: "partner_preview", sub: `partner:${person.id}`, partner_invite_id: person.id });
    assert.equal((await pool.query("select * from tester_invitations where id=$1", [result.invitation.id])).rows.length, 0);
  });
});
