const jwt = require("jsonwebtoken");
const { PartnerAccessError } = require("./partnerAccess");

const APPLE_STATES = new Set(["NOT_INVITED", "INVITED", "ACCEPTED", "INSTALLED", "REVOKED"]);
const APPLE_TESTABLE_BUILD_STATES = new Set(["IN_BETA_TESTING", "BETA_APPROVED"]);
const failure = code => new PartnerAccessError(503, code);
const resourceId = value => {
  if (!/^[A-Za-z0-9-]{1,80}$/.test(String(value || ""))) throw failure("apple_invalid_response");
  return value;
};

function createAppleTesterProvider(env = process.env, { fetchImpl = globalThis.fetch, now = Date.now } = {}) {
  const appId = String(env.ZIPPI_TESTER_APPLE_APP_ID || "6757395108");
  const groupId = String(env.ZIPPI_TESTER_APPLE_GROUP_ID || "");
  const issuer = env.ZIPPI_TESTER_APPLE_ISSUER_ID;
  const keyId = env.ZIPPI_TESTER_APPLE_KEY_ID;
  const key = env.ZIPPI_TESTER_APPLE_PRIVATE_KEY;
  const configured = !!(issuer && keyId && key && groupId && appId === "6757395108");
  async function request(path, body) {
    if (!configured) throw failure("apple_not_configured");
    try {
      const token = jwt.sign({ iss: issuer, aud: "appstoreconnect-v1", iat: Math.floor(now() / 1000), exp: Math.floor(now() / 1000) + 300 }, key,
        { algorithm: "ES256", keyid: keyId });
      const response = await fetchImpl(`https://api.appstoreconnect.apple.com/v1/${path}`, {
        method: body ? "POST" : "GET", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        ...(body ? { body: JSON.stringify(body) } : {}), redirect: "error", signal: AbortSignal.timeout(15000),
      });
      if (!response.ok) throw failure([401, 403].includes(response.status) ? "apple_authorization_failed" : response.status === 429 ? "apple_rate_limited" : "apple_unavailable");
      return response.status === 204 ? null : await response.json();
    } catch (error) {
      if (error instanceof PartnerAccessError) throw error;
      throw failure("apple_unavailable");
    }
  }
  // Pagination remains on a fixed API origin and endpoint; provider-supplied URLs are never fetched.
  async function collection(path) {
    const result = await request(path);
    if (!Array.isArray(result?.data)) throw failure("apple_invalid_response");
    // Fail closed rather than infer absence from an incomplete membership/build list.
    if (result.links?.next) throw failure("apple_result_limit");
    return result;
  }
  async function preflight() {
    if (!configured) throw failure("apple_not_configured");
    resourceId(groupId);
    const group = (await request(`betaGroups/${groupId}`))?.data;
    if (group?.attributes?.isInternalGroup !== false) throw failure("apple_group_mismatch");
    const app = (await request(`betaGroups/${groupId}/app`))?.data;
    if (app?.id !== appId || app?.attributes?.bundleId !== "com.heyzippi.zippi") throw failure("apple_group_mismatch");
    // The group/builds endpoint has no include parameter. Resolve only its member
    // IDs through /builds, where Apple supports include=buildBetaDetail.
    const members = (await collection(`betaGroups/${groupId}/builds?limit=200`)).data;
    const ids = members.filter(build => build.attributes?.expired === false && new Date(build.attributes?.expirationDate).getTime() > now()).map(build => resourceId(build.id));
    const eligible = [];
    for (let offset = 0; offset < ids.length; offset += 50) {
      const batch = ids.slice(offset, offset + 50);
      const builds = await collection(`builds?filter%5Bid%5D=${encodeURIComponent(batch.join(","))}&include=buildBetaDetail&limit=200`);
      for (const build of builds.data) {
        const detailId = build.relationships?.buildBetaDetail?.data?.id;
        const detail = builds.included?.find(item => item.type === "buildBetaDetails" && item.id === detailId);
        if (batch.includes(build.id) && build.attributes?.expired === false && new Date(build.attributes?.expirationDate).getTime() > now()
          && APPLE_TESTABLE_BUILD_STATES.has(detail?.attributes?.externalBuildState)) eligible.push(detail.attributes);
      }
    }
    if (!eligible.length) throw failure("apple_no_testable_build");
    return { autoNotify: eligible.some(detail => detail.autoNotifyEnabled === true) };
  }
  async function find(email) {
    const response = await collection(`betaTesters?filter%5Bemail%5D=${encodeURIComponent(email)}&limit=200`);
    const exact = response.data.filter(item => item.attributes?.email?.toLowerCase() === email);
    if (exact.length > 1) throw failure("apple_tester_ambiguous");
    return exact[0];
  }
  async function readTester(testerId) {
    // Apple's unscoped tester resource returns state: null. Status belongs to
    // this app, so request the exact tester with the documented apps filter.
    const id = resourceId(testerId);
    const response = await collection(`betaTesters?filter%5Bid%5D=${encodeURIComponent(id)}&filter%5Bapps%5D=${encodeURIComponent(appId)}&limit=200`);
    if (response.data.length !== 1 || response.data[0]?.id !== id) throw failure("apple_invalid_response");
    return response.data[0];
  }
  function project(tester) {
    if (!APPLE_STATES.has(tester?.attributes?.state)) throw failure("apple_invalid_response");
    return { testerId: resourceId(tester.id), state: tester.attributes.state };
  }
  async function sendInvitation(testerId, reserveNotification) {
    await reserveNotification(); // durable throttle before Apple's non-idempotent notification API
    await request("betaTesterInvitations", { data: { type: "betaTesterInvitations", relationships: {
      betaTester: { data: { type: "betaTesters", id: resourceId(testerId) } }, app: { data: { type: "apps", id: appId } },
    } } });
  }
  return {
    configured, preflight,
    async enroll(email, { reserveNotification }) {
      const readiness = await preflight();
      let tester = await find(email);
      if (!tester) {
        // Assign only the configured existing group. Never create groups, attach builds or edit distribution.
        tester = (await request("betaTesters", { data: { type: "betaTesters", attributes: { email }, relationships: {
          betaGroups: { data: [{ type: "betaGroups", id: groupId }] },
        } } }))?.data;
      } else {
        const memberships = await collection(`betaTesters/${resourceId(tester.id)}/betaGroups?limit=200`);
        if (!memberships.data.some(group => group.id === groupId)) {
          await request(`betaTesters/${tester.id}/relationships/betaGroups`, { data: [{ type: "betaGroups", id: groupId }] });
        }
      }
      const id = resourceId(tester?.id);
      // Re-read after membership assignment; don't manufacture an 'Invited' status.
      tester = await readTester(id);
      const memberships = await collection(`betaTesters/${id}/betaGroups?limit=200`);
      if (!memberships.data.some(group => group.id === groupId)) throw failure("apple_membership_unconfirmed");
      if (tester?.attributes?.state === "REVOKED") throw failure("apple_tester_revoked");
      if (tester?.attributes?.state === "NOT_INVITED" && !readiness.autoNotify) {
        await sendInvitation(id, reserveNotification);
        tester = await readTester(id);
      }
      return project(tester);
    },
    async refresh(testerId) {
      return project(await readTester(testerId));
    },
    async resend(testerId, { reserveNotification }) {
      await preflight();
      const memberships = await collection(`betaTesters/${resourceId(testerId)}/betaGroups?limit=200`);
      if (!memberships.data.some(group => group.id === groupId)) throw failure("apple_membership_unconfirmed");
      const state = project(await readTester(testerId));
      if (["ACCEPTED", "INSTALLED"].includes(state.state)) return state;
      if (state.state === "REVOKED") throw failure("apple_tester_revoked");
      await sendInvitation(testerId, reserveNotification);
      return project(await readTester(testerId));
    },
  };
}

function createAndroidTesterProvider(env = process.env) {
  // Audited existing public open-testing track; Google has no per-email enrollment API for it.
  const testingUrl = "https://play.google.com/apps/testing/com.heyzippi.app";
  const configured = env.ZIPPI_TESTER_ANDROID_MODE === "open_testing"
    && env.ZIPPI_TESTER_ANDROID_PREVIEW_BUILD_VERIFIED === "true";
  async function preflight() {
    if (!configured) throw failure("android_preview_build_unverified");
    return { testingUrl };
  }
  return { configured, preflight, async enroll() {
    await preflight();
    return { state: "OPT_IN_REQUIRED", testingUrl };
  } };
}

module.exports = { createAppleTesterProvider, createAndroidTesterProvider, APPLE_STATES };
