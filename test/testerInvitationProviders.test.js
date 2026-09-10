const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const jwt = require("jsonwebtoken");
const { createAppleTesterProvider, createAndroidTesterProvider } = require("../lib/testerInvitationProviders");
const { createResendMailAdapter } = require("../lib/partnerAccessResendMail");
const { invitationInstructions } = require("../lib/testerInvitationEmail");

function appleFixture({ existing = false, member = false, autoNotify = true, builds = true, internal = false, appId = "6757395108", failure = null, state = "INVITED", pagination = false, scopedMismatch = false, externalBuildState = "IN_BETA_TESTING", noInstallableBuilds = false } = {}) {
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const calls = []; let reservations = 0;
  const env = { ZIPPI_TESTER_APPLE_APP_ID: "6757395108", ZIPPI_TESTER_APPLE_GROUP_ID: "group-fixture", ZIPPI_TESTER_APPLE_ISSUER_ID: "issuer-fixture",
    ZIPPI_TESTER_APPLE_KEY_ID: "key-fixture", ZIPPI_TESTER_APPLE_PRIVATE_KEY: keys.privateKey.export({ type: "pkcs8", format: "pem" }) };
  const tester = () => ({ type: "betaTesters", id: "tester-fixture", attributes: { email: "qa@example.test", state } });
  const provider = createAppleTesterProvider(env, { fetchImpl: async (url, options) => {
    const token = options.headers.Authorization.slice(7);
    assert.equal(jwt.verify(token, keys.publicKey, { algorithms: ["ES256"], audience: "appstoreconnect-v1" }).iss, "issuer-fixture");
    assert.equal(options.redirect, "error");
    const path = new URL(url).pathname.replace("/v1/", ""); const body = options.body ? JSON.parse(options.body) : null;
    calls.push({ path, method: options.method, body });
    if (failure === path) return { ok: false, status: 403, json: async () => ({ secret: "provider-sensitive-value" }) };
    let data, included, links;
    if (path === "betaGroups/group-fixture") data = { attributes: { isInternalGroup: internal } };
    else if (path === "betaGroups/group-fixture/app") data = { id: appId, attributes: { bundleId: "com.heyzippi.zippi" } };
    else if (path === "betaGroups/group-fixture/builds") {
      assert.equal(new URL(url).searchParams.has("include"), false, "Apple's group builds endpoint does not support includes");
      data = builds ? [{ id: "build-fixture", attributes: { expired: false, expirationDate: "2099-01-01" } }] : [];
    } else if (path === "builds") {
      assert.equal(new URL(url).searchParams.get("filter[id]"), "build-fixture");
      assert.equal(new URL(url).searchParams.get("include"), "buildBetaDetail");
      data = builds ? [{ id: "build-fixture", attributes: { expired: false, expirationDate: "2099-01-01" }, relationships: { buildBetaDetail: { data: { id: "detail-fixture" } } } }] : [];
      included = [{ type: "buildBetaDetails", id: "detail-fixture", attributes: { externalBuildState, autoNotifyEnabled: autoNotify } }];
    } else if (path === "betaTesters" && !body) {
      const params = new URL(url).searchParams;
      if (params.has("filter[id]")) {
        assert.equal(params.get("filter[id]"), "tester-fixture");
        assert.equal(params.get("filter[apps]"), "6757395108");
        data = existing ? [{ ...tester(), ...(scopedMismatch ? { id: "wrong-tester" } : {}) }] : [];
      } else {
        data = existing ? [{ ...tester(), attributes: { email: "qa@example.test", state: null } }] : [];
      }
      links = pagination ? { next: "https://attacker.test" } : {};
    }
    else if (path === "betaTesters" && body) { existing = true; member = true; data = tester(); }
    else if (path === "betaTesters/tester-fixture/betaGroups") data = member ? [{ id: "group-fixture" }] : [];
    else if (path === "betaTesters/tester-fixture/relationships/betaGroups") { member = true; return { ok: true, status: 204 }; }
    else if (path === "betaTesters/tester-fixture") data = { ...tester(), attributes: { state: null } };
    else if (path === "betaTesterInvitations") {
      if (noInstallableBuilds) return { ok: false, status: 409, json: async () => ({ errors: [{ code: "STATE_ERROR.TESTER_INVITE.NO_INSTALLABLE_BUILDS", detail: "provider-sensitive-value" }] }) };
      state = "INVITED"; data = { id: "invitation-fixture" };
    }
    else throw new Error(`Unexpected mocked route ${path}`);
    return { ok: true, status: 200, json: async () => ({ data, included, links }) };
  } });
  return { provider, calls, reserveNotification: async () => { reservations++; }, get reservations() { return reservations; } };
}
test("Apple new tester creates only tester/group relationship, never edits build or app", async () => {
  const f = appleFixture();
  assert.equal((await f.provider.enroll("qa@example.test", f)).state, "INVITED");
  assert.deepEqual(f.calls.filter(c => c.method === "POST").map(c => c.path), ["betaTesters"]);
  assert.deepEqual(f.calls.find(c => c.method === "POST").body.data.relationships, { betaGroups: { data: [{ type: "betaGroups", id: "group-fixture" }] } });
});
test("Apple existing tester gets missing group once and duplicate enroll performs no writes", async () => {
  const f = appleFixture({ existing: true });
  await f.provider.enroll("qa@example.test", f); await f.provider.enroll("qa@example.test", f);
  assert.deepEqual(f.calls.filter(c => c.method === "POST").map(c => c.path), ["betaTesters/tester-fixture/relationships/betaGroups"]);
});
test("Apple automatic invitation is not duplicated by a manual notification", async () => {
  const f = appleFixture({ state: "NOT_INVITED" });
  assert.equal((await f.provider.enroll("qa@example.test", f)).state, "NOT_INVITED");
  assert.equal(f.reservations, 0);
});
test("Apple notifications disabled: explicit supported invitation reserved before sending", async () => {
  const f = appleFixture({ state: "NOT_INVITED", autoNotify: false });
  assert.equal((await f.provider.enroll("qa@example.test", f)).state, "INVITED"); assert.equal(f.reservations, 1);
  const call = f.calls.find(c => c.path === "betaTesterInvitations");
  assert.equal(call.body.data.relationships.app.data.id, "6757395108");
});
test("Apple invitation rejects loss of installable builds with a safe actionable error", async () => {
  const f = appleFixture({ existing: true, member: true, noInstallableBuilds: true });
  await assert.rejects(f.provider.resend("tester-fixture", f), error => error.code === "apple_no_testable_build" && !error.message.includes("provider-sensitive-value"));
  assert.equal(f.reservations, 1);
});
test("Apple unapproved or expired external build states cannot send invitations", async () => {
  for (const externalBuildState of ["BETA_APPROVED", "READY_FOR_BETA_TESTING", "READY_FOR_BETA_SUBMISSION", "WAITING_FOR_BETA_REVIEW", "IN_BETA_REVIEW", "BETA_REJECTED", "EXPIRED", "PROCESSING"]) {
    const f = appleFixture({ externalBuildState });
    await assert.rejects(f.provider.enroll("qa@example.test", f), error => error.code === "apple_no_testable_build");
    assert.equal(f.calls.some(c => c.method === "POST"), false);
  }
});
test("Apple resend uses supported API; accepted/installed users aren't emailed again", async () => {
  const f = appleFixture({ existing: true, member: true }); await f.provider.resend("tester-fixture", f); assert.equal(f.reservations, 1);
  const accepted = appleFixture({ existing: true, member: true, state: "INSTALLED" });
  await accepted.provider.resend("tester-fixture", accepted); assert.equal(accepted.reservations, 0);
});
test("Apple refresh uses the app-specific state even when the general tester state is null", async () => {
  const f = appleFixture({ existing: true, member: true, state: "INSTALLED" });
  assert.deepEqual(await f.provider.refresh("tester-fixture"), { testerId: "tester-fixture", state: "INSTALLED" });
  assert.deepEqual(f.calls.map(c => c.path), ["betaTesters"]);
  assert.equal(f.calls.every(c => c.method === "GET"), true);
});
test("Apple rejects a missing or mismatched app-scoped tester instead of inventing status", async () => {
  for (const options of [{}, { existing: true, scopedMismatch: true }, { existing: true, state: null }]) {
    const f = appleFixture(options);
    await assert.rejects(f.provider.refresh("tester-fixture"), error => error.code === "apple_invalid_response");
    assert.equal(f.calls.some(c => c.method === "POST"), false);
  }
});
for (const [name, options, code] of [
  ["no testable build", { builds: false }, "apple_no_testable_build"],
  ["internal group", { internal: true }, "apple_group_mismatch"],
  ["wrong app", { appId: "other-app" }, "apple_group_mismatch"],
  ["provider permissions", { failure: "betaGroups/group-fixture" }, "apple_authorization_failed"],
  ["incomplete result list", { pagination: true }, "apple_result_limit"],
]) test(`Apple rejects ${name} before any mutation`, async () => {
  const f = appleFixture(options);
  await assert.rejects(f.provider.enroll("qa@example.test", f), error => error.code === code && !error.message.includes("provider-sensitive-value"));
  assert.equal(f.calls.some(c => c.method === "POST"), false);
});
test("Apple missing credentials and Android unverified build fail closed", async () => {
  const apple = createAppleTesterProvider({}); assert.equal(apple.configured, false); await assert.rejects(apple.preflight());
  const android = createAndroidTesterProvider({ ZIPPI_TESTER_ANDROID_MODE: "open_testing" }); assert.equal(android.configured, false); await assert.rejects(android.enroll());
});
test("Android existing open channel returns opt-in required, never claims per-user enrollment", async () => {
  const provider = createAndroidTesterProvider({ ZIPPI_TESTER_ANDROID_MODE: "open_testing", ZIPPI_TESTER_ANDROID_PREVIEW_BUILD_VERIFIED: "true" });
  const expected = { state: "OPT_IN_REQUIRED", testingUrl: "https://play.google.com/apps/testing/com.heyzippi.app" };
  assert.deepEqual(await provider.enroll("qa@example.test"), expected);
  assert.deepEqual(await provider.enroll("qa@example.test"), expected);
});
test("Resend instructions reuse existing delivery adapter and stable idempotency header", async () => {
  const calls = [];
  const mail = createResendMailAdapter({ RESEND_API_KEY: "mock-provider-key", ZIPPI_PARTNER_EMAIL_FROM: "Zippi <preview@example.test>" }, { fetchImpl: async (url, options) => {
    calls.push({ url, options }); return { ok: true, json: async () => ({ id: "mock-message" }) };
  } });
  await mail.sendInstructions({ email: "qa@example.test", ...invitationInstructions("ios"), idempotencyKey: "test-key" });
  assert.equal(calls[0].options.headers["Idempotency-Key"], "test-key");
  assert.match(JSON.parse(calls[0].options.body).text, /same email address/);
  assert.equal(JSON.parse(calls[0].options.body).text.includes("mock-provider-key"), false);
  assert.match(invitationInstructions("android").text, /apps\/testing\/com.heyzippi.app/);
});
