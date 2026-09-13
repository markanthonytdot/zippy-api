const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const express = require('express');
const { createFeedbackReadBridgeRouter, FEEDBACK_ADMIN_ORIGIN } = require('../lib/feedbackReadBridge');
const { createAdminDashboardRouter } = require('../lib/adminDashboard');
const { parseFilters } = require('../lib/demoFeedback');
const secret = 'local-only-feedback-read-test-credential';
async function start(t, options = {}) {
  const calls = [];
  const service = { async report(query) { parseFilters(query); calls.push('report'); return { ok:true, source:query.source || 'all' }; },
    async *exportCsv(query) { parseFilters(query); calls.push('csv'); yield '\uFEFF"Source"\r\n'; yield '"' + (query.source || 'all') + '"\r\n'; } };
  const app=express();
  app.use('/internal/feedback-read',createFeedbackReadBridgeRouter({secret,flight:service,packages:service,...options}));
  app.use('/admin',createAdminDashboardRouter({adminSecret:'local-only-admin',sessionSecret:'local-only-session',demoFeedbackService:service,packageFeedbackService:service,feedbackAdminCanonical:options.canonical || false}));
  const server=app.listen(0,'127.0.0.1'); await once(server,'listening');
  t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
  return { base:`http://127.0.0.1:${server.address().port}`, calls };
}
test('feedback read bridge fails closed and grants no browser/admin/public-write authority',async t=>{
  const {base,calls}=await start(t);
  for (const headers of [{},{'x-zippi-feedback-read':'bad'},{'x-zippi-tester-admin':secret},{'x-zippi-feedback-read':secret,Origin:'https://heyzippi.com'},{'x-zippi-feedback-read':secret,'Sec-Fetch-Site':'same-origin'}]) {
    for(const path of ['demo-feedback','package-feedback','demo-feedback/export.csv','package-feedback/export.csv']) assert.equal((await fetch(base+'/internal/feedback-read/'+path,{headers})).status,401);
  }
  for(const path of ['/admin/api/demo-feedback','/admin/api/package-feedback','/admin/api/demo-feedback/export.csv','/admin/api/package-feedback/export.csv','/admin/api/android-testers']) assert.equal((await fetch(base+path,{headers:{'x-zippi-feedback-read':secret}})).status,401);
  for(const method of ['POST','PUT','DELETE','PATCH','HEAD','OPTIONS']) assert.equal((await fetch(base+'/internal/feedback-read/demo-feedback',{method,headers:{'x-zippi-feedback-read':secret}})).status,405);
  assert.equal((await fetch(base+'/internal/feedback-read/android-testers',{headers:{'x-zippi-feedback-read':secret}})).status,404);
  assert.deepEqual(calls,[]);
});
test('feedback bridge exposes only existing filtered reports and CSV with no-store/noindex',async t=>{
  const {base,calls}=await start(t);const headers={'x-zippi-feedback-read':secret};
  for(const name of ['demo-feedback','package-feedback']) {
    const report=await fetch(base+'/internal/feedback-read/'+name+'?source=test',{headers}); assert.equal(report.status,200);assert.equal((await report.json()).source,'test');assert.equal(report.headers.get('cache-control'),'no-store');assert.match(report.headers.get('x-robots-tag'),/noindex/);assert.equal(report.headers.get('set-cookie'),null);
    const csv=await fetch(base+'/internal/feedback-read/'+name+'/export.csv?source=test',{headers});assert.equal(csv.status,200);assert.match(csv.headers.get('content-type'),/text\/csv/);assert.match(await csv.text(),/"test"/);
    assert.equal((await fetch(base+'/internal/feedback-read/'+name+'/export.csv?source=bad%40email',{headers})).status,400);
  }
  assert.equal(calls.length,4);
});
test('missing read credential disables bridge; no cookie or signing secret is a fallback',async t=>{
  const {base}=await start(t,{secret:undefined});
  assert.equal((await fetch(base+'/internal/feedback-read/demo-feedback',{headers:{'x-zippi-feedback-read':secret}})).status,404);
});
test('optional old feedback bookmarks redirect only to fixed tester admin; existing API guard unchanged',async t=>{
  const {base}=await start(t,{canonical:true});
  for(const name of ['demo-feedback','package-feedback']) {
    const response=await fetch(base+'/admin/'+name+'?next=https://untrusted.example',{redirect:'manual'});
    assert.equal(response.status,302);assert.equal(response.headers.get('location'),FEEDBACK_ADMIN_ORIGIN+'/admin/'+name);assert.equal(response.headers.get('set-cookie'),null);
    assert.equal((await fetch(base+'/admin/api/'+name,{redirect:'manual'})).status,401);
    assert.equal((await fetch(base+'/admin/api/'+name+'/export.csv',{redirect:'manual'})).status,401);
  }
  const tester=await fetch(base+'/admin/partner-access',{redirect:'manual'});assert.equal(tester.headers.get('location'),'/admin/login');
});
