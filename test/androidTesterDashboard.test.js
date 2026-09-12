const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createAdminDashboardRouter, createAdminSessionToken } = require('../lib/adminDashboard');
const { createAndroidTesterRemote } = require('../lib/androidTesterRemote');
async function serve(t, app) {
  const server = await new Promise(resolve => { const s = app.listen(0,'127.0.0.1',()=>resolve(s)); });
  t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
  return `http://127.0.0.1:${server.address().port}`;
}
test('existing signed dashboard dispatches Android remotely and iOS locally with independent state', async t => {
  const calls = { android: [], ios: [] }; const bridge = 'local-dashboard-fixture-bridge-secret-only';
  const remote = createAndroidTesterRemote({ env: { ZIPPI_ANDROID_TESTER_REMOTE_ENABLED:'true', ZIPPI_ANDROID_TESTER_BRIDGE_SECRET:bridge },
    fetchImpl: async (url, options) => {
      assert.equal(new URL(url).hostname, 'zippy-api-6c59.onrender.com');
      assert.equal(options.headers['x-zippi-tester-admin'],bridge); assert.equal(options.redirect,'error');
      calls.android.push(options.body ? JSON.parse(options.body) : null);
      return {ok:true,json:async()=> options.body ? {ok:true,invitation:{authority:'production'}} : {ok:true,config:{authority:'production',enabled:true},invitations:[]}};
    } });
  const app = express(); app.use(express.json());
  app.use('/admin',createAdminDashboardRouter({ sessionSecret:'local-stage-session', androidTesterService:remote,
    partnerAccessService:{list:async()=>({ok:true,people:[],organizations:[]})},
    testerInvitationService:{list:async()=>({ok:true,config:{},invitations:[]}),run:async(...args)=>{calls.ios.push(args);return {ok:true};}} }));
  const origin = await serve(t,app);
  const cookie = `__Secure-zippi_admin_session=${createAdminSessionToken('local-stage-session',Date.now(),'local-stage-admin')}`;
  async function post(route, body, headers={}) { return fetch(`${origin}/admin/api/${route}`,{method:'POST',headers:{cookie,origin,'content-type':'application/json',...headers},body:JSON.stringify(body)}); }
  assert.equal((await fetch(`${origin}/admin/api/android-testers`)).status,401);
  assert.equal((await post('android-testers',{action:'prepare',platform:'android',email:'qa@heyzippi.test'},{origin:'https://foreign.example'})).status,403);
  assert.equal(calls.android.length,0);
  assert.equal((await post('android-testers',{action:'prepare',platform:'android',email:'qa@heyzippi.test',durationDays:1,secret:'injected',features:{checkout:true}})).status,200);
  assert.equal(calls.android.length,1); assert.equal(calls.ios.length,0); assert.equal(calls.android[0].actor,'local-stage-admin');
  assert.equal(calls.android[0].durationDays,1); assert.equal(calls.android[0].secret,undefined); assert.equal(calls.android[0].features,undefined);
  assert.equal((await post('tester-invitations',{platform:'ios',email:'ios-qa@heyzippi.test',durationDays:30})).status,200);
  assert.equal(calls.android.length,1); assert.equal(calls.ios.length,1); assert.equal(calls.ios[0][0].platform,'ios');
  assert.equal(calls.ios[0][0].durationDays,30);
  assert.deepEqual(calls.ios[0][3],{authenticatedAdmin:true});
  const page = await (await fetch(`${origin}/admin/partner-access`,{headers:{cookie}})).text();
  assert.match(page,/tester-google-email-help/); assert.match(page,/android-testers.js/); assert.match(page,/tester-invitations.js/);
  assert.ok(!page.includes(bridge));
  assert.match(page,/name="durationDays"/); assert.match(page,/value="7" selected/);
  const helper=await fetch(`${origin}/admin/assets/tester-access-duration.js`,{headers:{cookie}});
  assert.equal(helper.status,200);assert.match(await helper.text(),/expectedExpiresAt/);
});
test('missing Android bridge does not silently provision in staging', async () => {
  const remote = createAndroidTesterRemote({env:{},fetchImpl(){assert.fail('No remote call expected');}});
  assert.equal((await remote.list()).config.enabled,false);
  await assert.rejects(remote.run({action:'prepare',platform:'android'},'qa'),error=>error.code==='android_testers_unavailable');
});
