const { validBridgeSecret, input, SAFE_ERRORS } = require('./androidTesterRoutes');
const PRODUCTION_ENDPOINT = 'https://zippy-api-6c59.onrender.com/internal/android-tester-admin';
// Production is the only configured authority. The endpoint parameter is a local-test seam,
// never supplied by request input or environment variables.
function createAndroidTesterRemote({ env = process.env, fetchImpl = globalThis.fetch, endpoint = PRODUCTION_ENDPOINT } = {}) {
  const secret = env.ZIPPI_ANDROID_TESTER_BRIDGE_SECRET;
  const enabled = env.ZIPPI_ANDROID_TESTER_REMOTE_ENABLED === 'true' && validBridgeSecret(secret);
  async function call(body) {
    if (!enabled) return { ok: true, config: { enabled: false, authority: 'production' }, invitations: [] };
    try {
      const response = await fetchImpl(endpoint, { method: body ? 'POST' : 'GET', redirect: 'error',
        signal: AbortSignal.timeout(20000), headers: { 'x-zippi-tester-admin': secret, ...(body ? { 'Content-Type': 'application/json' } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}) });
      const value = await response.json();
      if (!response.ok) throw Object.assign(new Error('android_testers_unavailable'),
        SAFE_ERRORS.has(value?.error) ? { code: value.error, status: response.status } : {});
      if (value?.config?.authority !== 'production' && value?.invitation?.authority !== 'production') throw new Error('wrong_authority');
      return value;
    } catch (error) {
      throw Object.assign(new Error('android_testers_unavailable'), { code: SAFE_ERRORS.has(error?.code) ? error.code : 'android_testers_unavailable',
        status: SAFE_ERRORS.has(error?.code) ? error.status : 503 });
    }
  }
  return { list: () => call(), async run(body, actor) {
    if (!enabled) throw Object.assign(new Error('android_testers_unavailable'), { code: 'android_testers_unavailable', status: 503 });
    return call({ ...input(body), actor: String(actor || 'admin').slice(0,80) });
  } };
}
module.exports = { createAndroidTesterRemote, PRODUCTION_ENDPOINT };
