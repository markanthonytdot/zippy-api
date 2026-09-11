const jwt = require("jsonwebtoken");
const { AsyncLocalStorage } = require("node:async_hooks");
const { safeAppleMetadata } = require("./appleInvitationDiagnostics");
const { PartnerAccessError } = require("./partnerAccess");

const APPLE_STATES = new Set(["NOT_INVITED", "INVITED", "ACCEPTED", "INSTALLED", "REVOKED"]);
const APPLE_INVITED_STATES = new Set(["INVITED", "ACCEPTED", "INSTALLED"]);
const failure = code => new PartnerAccessError(503, code);
const resourceId = value => {
  if (!/^[A-Za-z0-9-]{1,80}$/.test(String(value || ""))) throw failure("apple_invalid_response");
  return value;
};

function createAppleTesterProvider(env = process.env, { fetchImpl = globalThis.fetch, now = Date.now, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  const appId = String(env.ZIPPI_TESTER_APPLE_APP_ID || "6757395108");
  const groupId = String(env.ZIPPI_TESTER_APPLE_GROUP_ID || "");
  const issuer = env.ZIPPI_TESTER_APPLE_ISSUER_ID;
  const keyId = env.ZIPPI_TESTER_APPLE_KEY_ID;
  const key = env.ZIPPI_TESTER_APPLE_PRIVATE_KEY;
  const configured = !!(issuer && keyId && key && groupId && appId === "6757395108");
  const operations = new AsyncLocalStorage();
  async function checkpoint(tester, pending = false) {
    const ctx = operations.getStore();
    if (!ctx) return;
    if (tester?.id) ctx.testerId = resourceId(tester.id);
    if (APPLE_STATES.has(tester?.attributes?.state)) ctx.state = tester.attributes.state;
    ctx.pending ||= pending;
    await ctx.save({ testerId: ctx.testerId, state: ctx.state, pending: ctx.pending, metadata: ctx.trace });
  }
  async function tracked(options, work) {
    const ctx = { trace: [], save: options?.checkpoint || (async () => {}), pending: false };
    return operations.run(ctx, async () => {
      try { return { ...await work(), metadata: safeAppleMetadata(ctx.trace) }; }
      catch (error) {
        if (error instanceof PartnerAccessError) {
          error.providerReference = { testerId: ctx.testerId, state: ctx.state, metadata: safeAppleMetadata(ctx.trace) };
          // A lost response after a possible write is ambiguous, not permission to resend.
          const last = ctx.trace.at(-1);
          error.confirmationUncertain = ctx.pending && ["apple_unavailable", "apple_invalid_response", "apple_rate_limited"].includes(error.code)
            && (ctx.accepted || last?.httpStatus == null || last?.httpStatus >= 500);
        }
        throw error;
      }
    });
  }
  function endpoint(path, body) {
    if (path === 'betaTesterInvitations') return 'tester_invitation';
    if (path.startsWith('betaTesters?')) return path.includes('filter%5Bid%5D') ? 'tester_status' : 'tester_lookup';
    if (path === 'betaTesters' && body) return 'tester_create';
    if (path.includes('/relationships/betaGroups')) return 'tester_group_assignment';
    if (path.startsWith('betaTesters/')) return 'tester_groups';
    if (path.startsWith('builds?')) return 'builds';
    if (path.endsWith('/app')) return 'group_app';
    if (path.includes('/builds?')) return 'group_builds';
    return 'group';
  }
  async function request(path, body) {
    if (!configured) throw failure("apple_not_configured");
    const ctx = operations.getStore();
    const entry = { endpoint: endpoint(path, body), method: body ? 'POST' : 'GET',
      httpStatus: null, category: 'transport', at: new Date(now()).toISOString() };
    try {
      const token = jwt.sign({ iss: issuer, aud: "appstoreconnect-v1", iat: Math.floor(now() / 1000), exp: Math.floor(now() / 1000) + 300 }, key,
        { algorithm: "ES256", keyid: keyId });
      const response = await fetchImpl(`https://api.appstoreconnect.apple.com/v1/${path}`, {
        method: entry.method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        ...(body ? { body: JSON.stringify(body) } : {}), redirect: "error", signal: AbortSignal.timeout(15000),
      });
      entry.httpStatus = response.status; entry.category = 'response';
      if (!response.ok) {
        const problem = await response.json().catch(() => null);
        entry.appleCode = problem?.errors?.[0]?.code;
        if (response.status === 409 && path === "betaTesterInvitations"
          && problem?.errors?.some(error => error.code === "STATE_ERROR.TESTER_INVITE.NO_INSTALLABLE_BUILDS")) {
          entry.appleCode = "STATE_ERROR.TESTER_INVITE.NO_INSTALLABLE_BUILDS";
          throw failure("apple_no_testable_build");
        }
        throw failure([401, 403].includes(response.status) ? "apple_authorization_failed" : response.status === 429 ? "apple_rate_limited" : "apple_unavailable");
      }
      if (ctx && body) ctx.accepted = true;
      if (response.status === 204) return null;
      try { return await response.json(); }
      catch { entry.category = 'invalid_response'; throw failure('apple_invalid_response'); }
    } catch (error) {
      if (error instanceof PartnerAccessError) throw error;
      throw failure("apple_unavailable");
    } finally {
      if (ctx) {
        ctx.trace = safeAppleMetadata([...ctx.trace, entry]);
        if (ctx.pending) await checkpoint();
      }
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
    if (group?.attributes?.isInternalGroup !== false || (env.ZIPPI_TESTER_APPLE_GROUP_NAME && group.attributes.name !== env.ZIPPI_TESTER_APPLE_GROUP_NAME)) throw failure("apple_group_mismatch");
    const app = (await request(`betaGroups/${groupId}/app`))?.data;
    if (app?.id !== appId || app?.attributes?.bundleId !== "com.heyzippi.zippi") throw failure("apple_group_mismatch");
    // The group/builds endpoint has no include parameter. Resolve only its member
    // IDs through /builds and validate approval/platform explicitly. Candidate
    // eligibility is not a promise of installability: Apple decides on enrollment.
    const members = (await collection(`betaGroups/${groupId}/builds?limit=200`)).data;
    const ids = members.filter(build => build.attributes?.expired === false && new Date(build.attributes?.expirationDate).getTime() > now()).map(build => resourceId(build.id));
    const eligible = [];
    for (let offset = 0; offset < ids.length; offset += 50) {
      const batch = ids.slice(offset, offset + 50);
      const builds = await collection(`builds?filter%5Bid%5D=${encodeURIComponent(batch.join(","))}&include=buildBetaDetail,betaAppReviewSubmission,preReleaseVersion&limit=200`);
      for (const build of builds.data) {
        const related = (relationship, type) => builds.included?.find(item => item.type === type && item.id === build.relationships?.[relationship]?.data?.id);
        const detail = related("buildBetaDetail", "buildBetaDetails");
        const review = related("betaAppReviewSubmission", "betaAppReviewSubmissions");
        const version = related("preReleaseVersion", "preReleaseVersions");
        if (batch.includes(build.id) && build.attributes?.processingState === "VALID"
          && build.attributes?.expired === false && new Date(build.attributes?.expirationDate).getTime() > now()
          && build.attributes?.buildAudienceType === "APP_STORE_ELIGIBLE"
          && review?.attributes?.betaReviewState === "APPROVED" && version?.attributes?.platform === "IOS"
          && ["IN_BETA_TESTING", "BETA_APPROVED"].includes(detail?.attributes?.externalBuildState)) eligible.push(detail.attributes);
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
  async function confirmedTester(id) {
    let tester;
    for (const delay of [0, 1000, 2000, 4000]) {
      if (delay) await sleep(delay);
      tester = await readTester(id);
      const result = project(tester);
      await checkpoint(tester);
      if (result.state === 'REVOKED') throw failure('apple_tester_revoked');
      if (APPLE_INVITED_STATES.has(result.state)) return result;
    }
    throw failure('apple_invitation_pending');
  }
  async function sendInvitation(testerId, reserveNotification) {
    await checkpoint({ id: testerId }, true);
    await reserveNotification(); // durable throttle before Apple's non-idempotent notification API
    await request("betaTesterInvitations", { data: { type: "betaTesterInvitations", relationships: {
      betaTester: { data: { type: "betaTesters", id: resourceId(testerId) } }, app: { data: { type: "apps", id: appId } },
    } } });
  }
  return {
    configured, preflight,
    async enroll(email, options) {
      return tracked(options, async () => {
        const readiness = await preflight();
        let tester = await find(email);
        if (!tester) {
          // Persist uncertainty before any write that may create/notify a tester.
          await checkpoint(null, true);
          tester = (await request("betaTesters", { data: { type: "betaTesters", attributes: { email }, relationships: {
            betaGroups: { data: [{ type: "betaGroups", id: groupId }] },
          } } }))?.data;
          await checkpoint(tester);
        } else {
          await checkpoint(tester);
          const memberships = await collection(`betaTesters/${resourceId(tester.id)}/betaGroups?limit=200`);
          if (!memberships.data.some(group => group.id === groupId)) {
            await checkpoint(tester, true);
            await request(`betaTesters/${tester.id}/relationships/betaGroups`, { data: [{ type: "betaGroups", id: groupId }] });
          }
        }
        const id = resourceId(tester?.id);
        tester = await readTester(id);
        await checkpoint(tester);
        const memberships = await collection(`betaTesters/${id}/betaGroups?limit=200`);
        if (!memberships.data.some(group => group.id === groupId)) throw failure("apple_membership_unconfirmed");
        if (tester?.attributes?.state === "REVOKED") throw failure("apple_tester_revoked");
        if (tester?.attributes?.state === "NOT_INVITED") {
          await checkpoint(tester, true);
          if (!readiness.autoNotify) await sendInvitation(id, options.reserveNotification);
          return confirmedTester(id);
        }
        return project(tester);
      });
    },
    // Reconciliation is GET-only, even after a timeout, restart or manual Retry.
    async reconcile(email, testerId, options = {}) {
      return tracked(options, async () => {
        let tester = testerId ? { id: resourceId(testerId) } : await find(email);
        if (!tester) throw failure('apple_invitation_pending');
        await checkpoint(tester, true);
        const memberships = await collection(`betaTesters/${tester.id}/betaGroups?limit=200`);
        if (!memberships.data.some(group => group.id === groupId)) throw failure('apple_membership_unconfirmed');
        return confirmedTester(tester.id);
      });
    },
    async refresh(testerId) { return project(await readTester(testerId)); },
    async resend(testerId, options) {
      return tracked(options, async () => {
        await preflight();
        const memberships = await collection(`betaTesters/${resourceId(testerId)}/betaGroups?limit=200`);
        if (!memberships.data.some(group => group.id === groupId)) throw failure("apple_membership_unconfirmed");
        const state = project(await readTester(testerId));
        if (["ACCEPTED", "INSTALLED"].includes(state.state)) return state;
        if (state.state === "REVOKED") throw failure("apple_tester_revoked");
        await sendInvitation(testerId, options.reserveNotification);
        return confirmedTester(testerId);
      });
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

module.exports = { createAppleTesterProvider, createAndroidTesterProvider, APPLE_STATES, APPLE_INVITED_STATES };
