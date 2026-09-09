const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { normalizeEmail, normalizeFeatures, normalizePlatforms, projectStatus, codeDigest, createDevelopmentMailAdapter, createPartnerAccessService } = require("../lib/partnerAccess");
const { createPartnerMailAdapter } = require("../lib/partnerAccessMail");
const { createPartnerAccessEnforcement, createPartnerAdminRouter, routeFeatures } = require("../lib/partnerAccessRoutes");

test("email normalization preserves plus/dot identities and rejects invalid input", () => {
  assert.equal(normalizeEmail("  Preview.Team+IOS@Porter.TEST  "), "preview.team+ios@porter.test");
  for (const email of ["bad", "a@b", "a b@example.test", "x\n@example.test", "ü@example.test"]) assert.throws(() => normalizeEmail(email));
});
test("feature flags are explicit booleans and extensible, platform flags fail closed", () => {
  assert.equal(normalizeFeatures({ future_feature: true }).future_feature, true);
  assert.throws(() => normalizeFeatures({ flights: "true" }));
  assert.throws(() => normalizeFeatures(JSON.parse('{"__proto__":true}')));
  assert.throws(() => normalizePlatforms(["web"]));
  assert.deepEqual(normalizePlatforms(["ios", "ios", "android"]), ["ios", "android"]);
});
test("server time solely decides expiry and start, and unavailable projections disable every feature", () => {
  const person = { status: "active", organization_status: "active", organization: "Fixture", starts_at: "2026-09-10T00:00:00Z", expires_at: "2026-09-17T00:00:00Z", platforms: ["ios"], features: { flights: true, checkout: true } };
  assert.equal(projectStatus(person, "ios", Date.parse("2026-09-09T00:00:00Z")).access, "scheduled");
  assert.equal(projectStatus(person, "ios", Date.parse("2026-09-10T00:00:00Z")).access, "active");
  assert.equal(projectStatus(person, "ios", Date.parse("2026-09-17T00:00:00Z")).access, "expired");
  assert.equal(projectStatus(person, "android", Date.parse("2026-09-11T00:00:00Z")).access, "unavailable");
  assert.equal(projectStatus({ ...person, revoked_at: "2026-09-11T00:00:00Z" }, "ios", Date.parse("2026-09-11T00:00:00Z")).features.checkout, false);
});
test("OTP digests are keyed, challenge bound, and do not contain code", () => {
  const digest = codeDigest("test-secret", "challenge-one", "314159");
  assert.equal(digest.length, 64);
  assert.notEqual(digest, codeDigest("other-secret", "challenge-one", "314159"));
  assert.notEqual(digest, codeDigest("test-secret", "challenge-two", "314159"));
  assert.equal(digest.includes("314159"), false);
});
test("production cannot enable development delivery and local adapter accepts only .test recipients", async () => {
  assert.equal(createDevelopmentMailAdapter({ enabled: true, production: true }).configured, false);
  assert.equal(createPartnerMailAdapter({ NODE_ENV: "production", ZIPPI_PARTNER_MAIL_ADAPTER: "development" }).configured, false);
  assert.equal(createPartnerMailAdapter({ AUTH_MODE: " PROD ", ZIPPI_PARTNER_MAIL_ADAPTER: "development" }).configured, false);
  const mail = createDevelopmentMailAdapter({ enabled: true });
  await assert.rejects(mail.send({ email: "real@example.com", code: "123456" }));
  await mail.send({ email: "preview@porter.test", code: "123456" });
  assert.equal(mail.read("preview@porter.test").code, "123456");
});
test("SMTP adapter requires credentials, verified TLS, no debug logs, and never contacts network in test", async () => {
  let configuration; let sent;
  const env = { ZIPPI_PARTNER_MAIL_ADAPTER: "smtp", ZIPPI_PARTNER_SMTP_HOST: "smtp.example.test", ZIPPI_PARTNER_SMTP_USER: "fixture", ZIPPI_PARTNER_SMTP_PASSWORD: "test-only", ZIPPI_PARTNER_SMTP_FROM: "preview@example.test", ZIPPI_PARTNER_SMTP_PORT: "587" };
  const mail = createPartnerMailAdapter(env, { createTransport(options) { configuration = options; return { async sendMail(value) { sent = value; } }; } });
  await mail.send({ email: "preview@porter.test", code: "314159", expiresInSeconds: 600 });
  assert.equal(configuration.requireTLS, true); assert.equal(configuration.tls.rejectUnauthorized, true); assert.equal(configuration.debug, false);
  assert.equal(sent.to, "preview@porter.test"); assert.match(sent.text, /314159/);
  assert.equal(createPartnerMailAdapter({ ...env, ZIPPI_PARTNER_SMTP_PASSWORD: "" }).configured, false);
});
test("all checkout aliases require checkout and their domain, combined context requires combined entitlement", () => {
  for (const url of ["/v1/flights/book", "/v1/flights/booking", "/v1/flights/booking/quote", "/v1/flights/payment/setup", "/flight/booking/confirm", "/v1/bookings", "/v1/bookings/create", "/v1/checkout/book", "/v1/checkout/confirm"]) {
    const features = routeFeatures({ originalUrl: url, method: "POST", headers: {} });
    assert.ok(features.includes("checkout"), url); assert.ok(features.includes("flights"), url);
  }
  assert.deepEqual(routeFeatures({ originalUrl: "/v1/hotels/prices", method: "POST", headers: { "x-zippi-feature": "combinedTrip" } }), ["hotels", "combinedTrip"]);
  assert.deepEqual(routeFeatures({ originalUrl: "/V1/FLIGHTS/PAYMENT/SETUP/", method: "POST", headers: {} }), ["flights", "checkout"]);
});
async function enforce({ claims, required = false, access = "active", features = { flights: true, hotels: true, combinedTrip: true, checkout: false }, url = "/v1/flights/search", headers = {}, verified = !!claims }) {
  const result = { next: false, status: 200 }; let checks = 0;
  const gate = createPartnerAccessEnforcement({ required, service: { async status() { checks++; return { access, features }; } } });
  await gate({ originalUrl: url, method: "POST", headers, authClaims: claims, userIdVerified: verified }, { status(value) { result.status = value; return this; }, json(value) { result.body = value; return this; } }, () => { result.next = true; });
  return { ...result, checks };
}
test("normal and public sessions retain behavior; required mode rejects anonymous travel", async () => {
  assert.equal((await enforce({})).next, true);
  assert.equal((await enforce({ required: true })).status, 401);
  assert.equal((await enforce({ required: true, claims: { sub: "normal-apple" } })).next, true);
  assert.equal((await enforce({ required: true, url: "/v1/places/eta" })).next, true);
});
test("every partner request rechecks DB; revoked and feature-disabled requests are denied", async () => {
  const claims = { sub: "partner:fixture", auth_method: "partner_preview" };
  assert.equal((await enforce({ claims })).checks, 1);
  assert.equal((await enforce({ claims, access: "revoked" })).status, 403);
  assert.equal((await enforce({ claims, url: "/v1/checkout/confirm" })).status, 403);
  assert.equal((await enforce({ claims, url: "/partner-access/status", access: "expired" })).next, true);
  const invalid = `x.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.x`;
  assert.equal((await enforce({ headers: { authorization: `Bearer ${invalid}` } })).status, 401);
});
test("admin router rejects missing admin identity, cross-origin and form writes", async () => {
  const router = createPartnerAdminRouter({ service: {} });
  const middleware = router.stack[0].handle;
  for (const [admin, origin, json, expected] of [[null, "https://admin.test", true, 401], [{}, "https://evil.test", true, 403], [{}, "https://admin.test", false, 403], [{}, "https://admin.test", true, 200]]) {
    let status = 200; let next = false;
    middleware({ zippiAdmin: admin, method: "POST", protocol: "https", get(name) { return name === "host" ? "admin.test" : origin; }, is() { return json; } }, { status(value) { status = value; return this; }, json() {} }, () => { next = true; });
    assert.equal(status, expected); assert.equal(next, expected === 200);
  }
});

const databaseUrl = process.env.PARTNER_TEST_DATABASE_URL;
test("PostgreSQL Partner Access lifecycle and concurrent security contracts", { skip: !databaseUrl }, async t => {
  const parsed = new URL(databaseUrl);
  assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname), "Tests require an isolated loopback database");
  const schema = `partner_test_${crypto.randomBytes(8).toString("hex")}`;
  const setupPool = new Pool({ connectionString: databaseUrl, ssl: false });
  await setupPool.query(`create schema ${schema}`);
  const pool = new Pool({ connectionString: databaseUrl, ssl: false, options: `-c search_path=${schema}` });
  t.after(async () => { await pool.end(); await setupPool.query(`drop schema ${schema} cascade`); await setupPool.end(); });
  await pool.query(fs.readFileSync(path.join(__dirname, "../migrations/013_partner_access.sql"), "utf8"));
  let clock = Date.parse("2026-09-10T12:00:00Z"); let serial = 0;
  const mail = createDevelopmentMailAdapter({ enabled: true, fixedCode: "314159" });
  const { SignJWT, jwtVerify } = await import("jose"); const key = new TextEncoder().encode("only-for-local-integration-tests");
  const service = createPartnerAccessService({ dbPool: pool, secret: "only-for-local-integration-tests", now: () => clock, mailAdapter: mail,
    signToken: (subject, claims) => new SignJWT(claims).setProtectedHeader({ alg: "HS256" }).setSubject(subject).setIssuer("zippy-api").setAudience("zippy-ios").setIssuedAt().setExpirationTime("30d").sign(key),
  });
  const organization = (await service.createOrganization({ name: "Porter Fixture", allowedEmailDomains: ["PORTER.TEST"] }, "test-admin")).organization;
  async function fixture(options = {}) {
    serial++; const email = `preview${serial}@porter.test`; const ip = `192.0.2.${serial}`;
    const person = (await service.createPerson({ email, organizationId: organization.id, durationDays: 7, ...options }, "test-admin")).person;
    return { person, email, ip, platform: "ios" };
  }
  async function verify(input) { const reply = await service.verifyCode({ ...input, code: "314159" }); const claims = (await jwtVerify(reply.token, key, { issuer: "zippy-api", audience: "zippy-ios" })).payload; return { reply, claims }; }
  await t.test("mocked Resend preserves approved-only delivery, OTP security and live entitlement changes", async () => {
    const messages = []; let deliveryFails = false;
    const resend = createPartnerMailAdapter({ ZIPPI_PARTNER_MAIL_ADAPTER: "resend", RESEND_API_KEY: "test-only", ZIPPI_PARTNER_EMAIL_FROM: "preview@example.test" }, {
      fetchImpl: async (_url, options) => {
        messages.push(JSON.parse(options.body));
        return { ok: !deliveryFails, json: async () => ({ id: "mock-message-id" }) };
      },
    });
    const resendService = createPartnerAccessService({ dbPool: pool, secret: "only-for-local-integration-tests", now: () => clock, mailAdapter: resend,
      signToken: (subject, claims) => new SignJWT(claims).setProtectedHeader({ alg: "HS256" }).setSubject(subject).setIssuer("zippy-api").setAudience("zippy-ios").setIssuedAt().setExpirationTime("30d").sign(key),
    });
    const input = await fixture({ platforms: ["ios"], features: { flights: true, hotels: true, combinedTrip: true, checkout: false } });
    const unknown = { email: "resend-unapproved@porter.test", platform: "ios", ip: "192.0.2.201" };
    const unknownReply = await resendService.requestCode(unknown);
    assert.equal(messages.length, 0);
    assert.deepEqual(await resendService.requestCode(input), unknownReply);
    assert.equal(messages.length, 1);
    const code = messages[0].text.match(/\b\d{6}\b/)[0];
    const row = (await pool.query("select * from partner_verifications where person_id=$1", [input.person.id])).rows[0];
    assert.equal(row.code_digest, codeDigest("only-for-local-integration-tests", row.id, code));
    assert.equal(Object.hasOwn(row, "code"), false);
    assert.equal(new Date(row.expires_at).getTime() - clock, 600000);
    await resendService.requestCode(input); assert.equal(messages.length, 1);
    const reply = await resendService.verifyCode({ ...input, code });
    const claims = (await jwtVerify(reply.token, key, { issuer: "zippy-api", audience: "zippy-ios" })).payload;
    assert.equal(reply.partnerAccess.features.checkout, false);
    await assert.rejects(resendService.verifyCode({ ...input, code }), error => error.code === "invalid_code");
    await service.changePerson(input.person.id, "revoke", {}, "test-admin");
    assert.equal((await resendService.status(claims)).access, "revoked");
    clock += 60000; await resendService.requestCode(input); assert.equal(messages.length, 1);
    await service.changePerson(input.person.id, "update", { status: "active", features: { combinedTrip: false } }, "test-admin");
    const restored = await resendService.status(claims);
    assert.equal(restored.access, "active"); assert.equal(restored.features.combinedTrip, false); assert.equal(restored.features.checkout, false);
    deliveryFails = true;
    assert.deepEqual(await resendService.requestCode(input), unknownReply);
    assert.equal(messages.length, 2);
    const failedCode = messages[1].text.match(/\b\d{6}\b/)[0];
    await assert.rejects(resendService.verifyCode({ ...input, code: failedCode }), error => error.code === "invalid_code");
    const latest = (await pool.query("select * from partner_verifications where person_id=$1 order by created_at desc limit 1", [input.person.id])).rows[0];
    assert.ok(latest.consumed_at);
    const audit = (await pool.query("select metadata from partner_access_audit where person_id=$1 and event='code_delivery_failed'", [input.person.id])).rows;
    assert.deepEqual(audit, [{ metadata: { platform: "ios" } }]);
  });
  await t.test("approved case-normalized email requests code; code database stores only keyed digest", async () => {
    const input = await fixture(); const reply = await service.requestCode({ ...input, email: ` ${input.email.toUpperCase()} ` });
    assert.equal(reply.ok, true); assert.equal(mail.read(input.email).code, "314159");
    const row = (await pool.query("select * from partner_verifications where person_id=$1", [input.person.id])).rows[0];
    assert.equal(Object.keys(row).includes("code"), false); assert.equal(row.code_digest.length, 64); assert.equal(JSON.stringify(row).includes('"314159"'), false);
  });
  await t.test("unapproved address cannot activate and gets same code request reply", async () => {
    const input = await fixture(); const unknown = { email: "unapproved@porter.test", platform: "ios", ip: "192.0.2.200" };
    assert.deepEqual(await service.requestCode(input), await service.requestCode(unknown)); assert.equal(mail.read(unknown.email), null);
    await assert.rejects(verify(unknown), error => error.code === "invalid_code");
  });
  await t.test("wrong code increments attempts and limit locks even correct code", async () => {
    const input = await fixture(); await service.requestCode(input);
    for (let n = 0; n < 5; n++) await assert.rejects(service.verifyCode({ ...input, code: "000000" }), error => error.code === "invalid_code");
    await assert.rejects(verify(input), error => error.code === "invalid_code");
    assert.equal((await pool.query("select attempts from partner_verifications where person_id=$1", [input.person.id])).rows[0].attempts, 5);
  });
  await t.test("expiry at exact ten-minute server deadline rejects verification", async () => {
    const input = await fixture(); await service.requestCode(input); clock += 600000;
    await assert.rejects(verify(input), error => error.code === "invalid_code");
  });
  await t.test("resend cooldown suppresses duplicate delivery and invalidates earlier challenge after cooldown", async () => {
    const input = await fixture(); await service.requestCode(input); await service.requestCode(input);
    assert.equal((await pool.query("select count(*) from partner_verifications where person_id=$1", [input.person.id])).rows[0].count, "1");
    clock += 60000; await service.requestCode(input);
    const rows = (await pool.query("select * from partner_verifications where person_id=$1 order by created_at", [input.person.id])).rows;
    assert.equal(rows.length, 2); assert.ok(rows[0].consumed_at); assert.equal(rows[1].consumed_at, null);
  });
  await t.test("concurrent one-time verification grants exactly one JWT", async () => {
    const input = await fixture(); await service.requestCode(input);
    const results = await Promise.allSettled([verify(input), verify(input)]);
    assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  });
  await t.test("same invite yields same identity expiry and feature set on both platforms", async () => {
    const input = await fixture(); await service.requestCode(input); const ios = await verify(input);
    clock += 60000; const androidInput = { ...input, platform: "android" }; await service.requestCode(androidInput); const android = await verify(androidInput);
    assert.equal(ios.claims.sub, android.claims.sub); assert.equal(ios.claims.auth_method, "partner_preview");
    assert.equal(ios.reply.partnerAccess.expiresAt, android.reply.partnerAccess.expiresAt); assert.deepEqual(ios.reply.partnerAccess.features, android.reply.partnerAccess.features);
    assert.equal(ios.claims.platform, "ios"); assert.equal(android.claims.platform, "android");
  });
  await t.test("future access verifies session but stays scheduled until server start", async () => {
    const input = await fixture({ startsAt: new Date(clock + 3600000).toISOString() }); await service.requestCode(input); const { claims } = await verify(input);
    assert.equal((await service.status(claims)).access, "scheduled"); clock += 3600000;
    assert.equal((await service.status(claims)).access, "active");
  });
  await t.test("expiry audit once and extension restores same already-verified JWT", async () => {
    const input = await fixture(); await service.requestCode(input); const { claims } = await verify(input); clock += 7 * 86400000;
    assert.equal((await service.status(claims)).access, "expired"); await service.status(claims);
    assert.equal((await pool.query("select count(*) from partner_access_audit where person_id=$1 and event='expired'", [input.person.id])).rows[0].count, "1");
    await service.changePerson(input.person.id, "extend", { durationDays: 7 }, "test-admin");
    assert.equal((await service.status(claims)).access, "active");
  });
  await t.test("revocation immediate, extension alone cannot silently undo revocation, explicit restoration works", async () => {
    const input = await fixture(); await service.requestCode(input); const { claims } = await verify(input);
    await service.changePerson(input.person.id, "revoke", {}, "test-admin"); assert.equal((await service.status(claims)).access, "revoked");
    await service.changePerson(input.person.id, "extend", { durationDays: 3 }, "test-admin"); assert.equal((await service.status(claims)).access, "revoked");
    await service.changePerson(input.person.id, "update", { status: "active" }, "test-admin"); assert.equal((await service.status(claims)).access, "active");
  });
  await t.test("platform flags prevent wrong platform verification and revoke an already-verified platform remotely", async () => {
    const input = await fixture(); await service.requestCode(input); await assert.rejects(verify({ ...input, platform: "android" })); const { claims } = await verify(input);
    await service.changePerson(input.person.id, "update", { platforms: ["android"] }, "test-admin"); assert.equal((await service.status(claims)).access, "unavailable");
  });
  await t.test("remote feature update uses fresh flags and operator list contains no searches", async () => {
    const input = await fixture(); await service.requestCode(input); const { claims } = await verify(input);
    await service.changePerson(input.person.id, "update", { features: { flights: false, checkout: false, future_feature: true } }, "test-admin");
    const status = await service.status(claims); assert.equal(status.features.flights, false); assert.equal(status.features.future_feature, true);
    const person = (await service.list()).people.find(row => row.id === input.person.id); assert.ok(person.activatedAt); assert.ok(person.lastCheckedAt);
    assert.equal(Object.hasOwn(person, "searches"), false); assert.equal(Object.hasOwn(person, "conversation"), false);
  });
  await t.test("durable per-email rate limiting includes unapproved recipients", async () => {
    const input = { email: "rate-limit@porter.test", platform: "ios", ip: "192.0.2.199" };
    for (let n = 0; n < 5; n++) await service.requestCode(input);
    await assert.rejects(service.requestCode(input), error => error.status === 429);
    const rows = (await pool.query("select * from partner_access_rate_limits")).rows; assert.equal(JSON.stringify(rows).includes(input.email), false);
  });
  await t.test("per-IP and per-device request limits survive rotating unapproved emails", async () => {
    for (let n = 0; n < 20; n++) await service.requestCode({ email: `ip${n}@porter.test`, platform: "ios", ip: "192.0.2.198" });
    await assert.rejects(service.requestCode({ email: "ipblocked@porter.test", platform: "ios", ip: "192.0.2.198" }), error => error.status === 429);
    for (let n = 0; n < 10; n++) await service.requestCode({ email: `device${n}@porter.test`, platform: "ios", ip: `192.0.2.${150 + n}`, deviceId: "one-test-device" });
    await assert.rejects(service.requestCode({ email: "deviceblocked@porter.test", platform: "ios", ip: "192.0.2.170", deviceId: "one-test-device" }), error => error.status === 429);
  });
  await t.test("simultaneous requests obey resend cooldown under the PostgreSQL email lock", async () => {
    const input = await fixture(); await Promise.all([service.requestCode(input), service.requestCode(input)]);
    assert.equal((await pool.query("select count(*) from partner_verifications where person_id=$1", [input.person.id])).rows[0].count, "1");
  });
  await t.test("organization disablement immediately blocks status and email delivery", async () => {
    const org = (await service.createOrganization({ name: "Disabled Fixture" }, "test-admin")).organization;
    const input = await fixture({ organizationId: org.id }); await service.requestCode(input); const { claims } = await verify(input);
    await pool.query("update partner_organizations set status='disabled' where id=$1", [org.id]);
    assert.equal((await service.status(claims)).access, "revoked");
    clock += 60000; await service.requestCode(input);
    assert.equal((await pool.query("select count(*) from partner_verifications where person_id=$1", [input.person.id])).rows[0].count, "1");
  });
  await t.test("domain is restriction only, duplicate collisions explicit and normal token remains independent", async () => {
    const input = await fixture(); await assert.rejects(service.createPerson({ email: input.email.toUpperCase(), organizationId: organization.id, durationDays: 3 }, "test-admin"), error => error.code === "email_already_invited");
    await assert.rejects(service.createPerson({ email: "other@wrong.test", organizationId: organization.id, durationDays: 3 }, "test-admin"), error => error.code === "email_domain_not_allowed");
    assert.equal((await service.status({ sub: "normal-apple" })).access, "none");
    await assert.rejects(service.status({ sub: "normal-apple", auth_method: "partner_preview", partner_invite_id: input.person.id, platform: "ios" }), error => error.status === 401);
  });
  await t.test("account deletion removes email and OTP records and invalidates a retained partner JWT", async () => {
    const input = await fixture(); await service.requestCode(input); const { claims } = await verify(input);
    await service.deleteAccount(claims);
    assert.equal((await service.status(claims)).access, "unavailable");
    assert.equal((await pool.query("select count(*) from partner_people where id=$1", [input.person.id])).rows[0].count, "0");
    assert.equal((await pool.query("select count(*) from partner_verifications where person_id=$1", [input.person.id])).rows[0].count, "0");
    assert.equal((await pool.query("select count(*) from partner_access_audit where event='account_deleted' and person_id is null")).rows[0].count, "1");
  });
});
